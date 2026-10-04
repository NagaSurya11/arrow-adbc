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

using Apache.Arrow.Adbc.Drivers.Apache.Hive2;
using Apache.Hive.Service.Rpc.Thrift;

namespace Apache.Arrow.Adbc.Drivers.Apache.Spark
{
    internal class SparkStatement : HiveServer2Statement
    {
        internal SparkStatement(SparkConnection connection)
            : base(connection)
        {
        }

        protected override void SetStatementProperties(TExecuteStatementReq statement)
        {
            // This seems like a good idea to have the server timeout so it doesn't keep processing unnecessarily.
            // Set in combination with a CancellationToken.
            statement.QueryTimeout = QueryTimeoutSeconds;

            // Run async so ExecuteStatement returns at once and the 500ms poll loop keeps the
            // connection busy. Synchronously the socket is silent for the whole query, and the
            // service mesh drops an idle TCP connection after 1h, which cancels the query.
            statement.RunAsync = true;
        }

        public override string AssemblyName => HiveServer2Connection.s_assemblyName;

        public override string AssemblyVersion => HiveServer2Connection.s_assemblyVersion;
    }
}
