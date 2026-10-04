/*
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements.  See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Text.Json;

namespace Apache.Arrow.Adbc.Drivers.Apache.Spark
{
    /// <summary>
    /// Fetches an OAuth2 client_credentials access token (Keycloak, Azure Entra ID, ...) for
    /// <see cref="SparkAuthType.Oidc"/> and caches it in-process.
    ///
    /// Caching mirrors the credential proxy: a token is reused for
    /// min(refresh_seconds (default 150), expires_in / 2), then the next caller fetches a new
    /// one. Refresh is lazy (no background thread) and single-flight (one lock, so concurrent
    /// connections trigger at most one token request). If a refresh fails but the previous
    /// token has not actually expired yet, the previous token is returned.
    /// Uses only HttpClient + System.Text.Json DOM APIs, which are NativeAOT-safe.
    /// </summary>
    internal static class SparkOidcTokenProvider
    {
        internal const int DefaultRefreshSeconds = 150;

        private static readonly HttpClient s_http = new() { Timeout = TimeSpan.FromSeconds(30) };
        private static readonly object s_lock = new();
        private static readonly Dictionary<string, CachedToken> s_cache = new();

        private sealed class CachedToken
        {
            public CachedToken(string token, DateTime refreshAtUtc, DateTime expiresAtUtc)
            {
                Token = token;
                RefreshAtUtc = refreshAtUtc;
                ExpiresAtUtc = expiresAtUtc;
            }

            public string Token { get; }
            public DateTime RefreshAtUtc { get; }
            public DateTime ExpiresAtUtc { get; }
        }

        internal static void ValidateOptions(IReadOnlyDictionary<string, string> properties)
        {
            foreach (string key in new[] { SparkParameters.OidcTokenUrl, SparkParameters.OidcClientId, SparkParameters.OidcClientSecret })
            {
                if (string.IsNullOrWhiteSpace(Get(properties, key)))
                {
                    throw new ArgumentException(
                        $"Parameter '{SparkParameters.AuthType}' is set to '{SparkAuthTypeConstants.Oidc}' but parameter '{key}' is not set. Please provide a value for this parameter.",
                        nameof(properties));
                }
            }

            string tokenUrl = Get(properties, SparkParameters.OidcTokenUrl)!;
            if (!Uri.TryCreate(tokenUrl, UriKind.Absolute, out Uri? uri) ||
                (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                throw new ArgumentException(
                    $"Parameter '{SparkParameters.OidcTokenUrl}' must be an absolute http(s) URL.",
                    nameof(properties));
            }

            ParseRefreshSeconds(properties);
        }

        /// <summary>SASL user name: the explicit `username` option, else the OIDC client id.</summary>
        internal static string ResolveUsername(IReadOnlyDictionary<string, string> properties)
        {
            string? username = Get(properties, AdbcOptions.Username);
            return string.IsNullOrWhiteSpace(username) ? Get(properties, SparkParameters.OidcClientId)! : username!;
        }

        internal static string GetToken(IReadOnlyDictionary<string, string> properties)
        {
            string tokenUrl = Get(properties, SparkParameters.OidcTokenUrl)!;
            string clientId = Get(properties, SparkParameters.OidcClientId)!;
            string clientSecret = Get(properties, SparkParameters.OidcClientSecret)!;
            string? scope = Get(properties, SparkParameters.OidcScope);
            int refreshSeconds = ParseRefreshSeconds(properties);

            string key = string.Join("\n", tokenUrl, clientId, clientSecret, scope ?? string.Empty);

            lock (s_lock)
            {
                DateTime now = DateTime.UtcNow;
                s_cache.TryGetValue(key, out CachedToken? cached);
                if (cached != null && now < cached.RefreshAtUtc)
                {
                    return cached.Token;
                }

                try
                {
                    CachedToken fresh = Fetch(tokenUrl, clientId, clientSecret, scope, refreshSeconds, now);
                    s_cache[key] = fresh;
                    return fresh.Token;
                }
                catch (Exception) when (cached != null && now < cached.ExpiresAtUtc)
                {
                    // Refresh failed (Keycloak blip) but the previous token is still valid.
                    return cached.Token;
                }
            }
        }

        private static CachedToken Fetch(string tokenUrl, string clientId, string clientSecret, string? scope, int refreshSeconds, DateTime now)
        {
            List<KeyValuePair<string, string>> form = new()
            {
                new("grant_type", "client_credentials"),
                new("client_id", clientId),
                new("client_secret", clientSecret),
            };
            if (!string.IsNullOrWhiteSpace(scope))
            {
                form.Add(new("scope", scope!));
            }

            using HttpRequestMessage request = new(HttpMethod.Post, tokenUrl)
            {
                Content = new FormUrlEncodedContent(form),
            };
            // Sync over async on purpose: CreateTransport is synchronous, and HttpClient.Send /
            // ReadAsStream do not exist on this project's netstandard2.0 / net472 targets.
            using HttpResponseMessage response = s_http.SendAsync(request).GetAwaiter().GetResult();
            string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

            if (!response.IsSuccessStatusCode)
            {
                // The response body never contains the client secret; truncate to keep errors short.
                string snippet = body.Length > 300 ? body.Substring(0, 300) : body;
                throw new InvalidOperationException(
                    $"OIDC token request to '{tokenUrl}' failed: HTTP {(int)response.StatusCode}. {snippet}");
            }

            using JsonDocument doc = JsonDocument.Parse(body);
            JsonElement root = doc.RootElement;
            string? accessToken = root.TryGetProperty("access_token", out JsonElement tokenElement) &&
                                  tokenElement.ValueKind == JsonValueKind.String
                ? tokenElement.GetString()
                : null;
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new InvalidOperationException($"OIDC token response from '{tokenUrl}' has no 'access_token'.");
            }

            int expiresIn = root.TryGetProperty("expires_in", out JsonElement expiresElement) &&
                            expiresElement.ValueKind == JsonValueKind.Number &&
                            expiresElement.TryGetInt32(out int parsed)
                ? parsed
                : 0;

            double reuseSeconds = refreshSeconds;
            if (expiresIn > 0)
            {
                reuseSeconds = Math.Min(reuseSeconds, expiresIn / 2.0);
            }
            double lifetimeSeconds = expiresIn > 0 ? expiresIn : reuseSeconds;

            return new CachedToken(accessToken!, now.AddSeconds(reuseSeconds), now.AddSeconds(lifetimeSeconds));
        }

        private static int ParseRefreshSeconds(IReadOnlyDictionary<string, string> properties)
        {
            string? raw = Get(properties, SparkParameters.OidcRefreshSeconds);
            if (string.IsNullOrWhiteSpace(raw))
            {
                return DefaultRefreshSeconds;
            }
            if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int seconds) || seconds <= 0)
            {
                throw new ArgumentException(
                    $"Parameter '{SparkParameters.OidcRefreshSeconds}' must be a positive integer (seconds).",
                    nameof(properties));
            }
            return seconds;
        }

        private static string? Get(IReadOnlyDictionary<string, string> properties, string key) =>
            properties.TryGetValue(key, out string? value) ? value : null;
    }
}
