/*******************************************************************************
 * Copyright 2012 Apigee Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package org.usergrid.mongo.commands;


import java.util.*;

import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.mongo.MongoChannelHandler;
import org.usergrid.mongo.protocol.OpQuery;
import org.usergrid.mongo.protocol.OpReply;
import org.usergrid.security.shiro.utils.SubjectUtils;

import static org.usergrid.utils.MapUtils.map;


public class ListDatabases extends MongoCommand {


	final static double DEFAULT_SIZE = 1024 * 1024 * 1024.0;

	@SuppressWarnings("unchecked")
	@Override
	public OpReply execute(MongoChannelHandler handler,
			ChannelHandlerContext ctx, MessageEvent e, OpQuery opQuery) {
		Iterator<ApplicationInfo> applications = SubjectUtils.getAuthorizationInfo().getApplications().iterator();
		List<Map<String, Object>> dbs = new ArrayList<Map<String, Object>>();

		while(applications.hasNext()) {
			dbs.add((Map<String, Object>) map("name", applications.next().getName(), "sizeOnDisk",
					DEFAULT_SIZE, "empty", false));
		}
		OpReply reply = new OpReply(opQuery);
		reply.addDocument(map("databases", dbs, "totalSize", 1.0, "ok", 1.0));
		return reply;
	}

}
