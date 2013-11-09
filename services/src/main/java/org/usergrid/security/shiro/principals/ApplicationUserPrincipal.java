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
package org.usergrid.security.shiro.principals;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.persistence.Entity;
import org.usergrid.persistence.EntityManager;
import org.usergrid.persistence.Results;
import org.usergrid.persistence.SimpleEntityRef;
import org.usergrid.persistence.entities.Group;
import org.usergrid.persistence.entities.User;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.security.shiro.credentials.AccessTokenCredentials;
import org.usergrid.security.tokens.TokenInfo;

import static org.usergrid.security.shiro.utils.SubjectUtils.getPermissionFromPath;

public class ApplicationUserPrincipal extends UserPrincipal {

	public ApplicationUserPrincipal(UUID applicationId, UserInfo user) {
		super(applicationId, user);
	}


  @Override
  public void populateAuthorizatioInfo(UsergridAuthorizationInfo info) {

    role(info, principal, ROLE_APPLICATION_USER);

    UUID applicationId = ((ApplicationUserPrincipal) principal)
        .getApplicationId();

    AccessTokenCredentials tokenCredentials = ((ApplicationUserPrincipal) principal)
        .getAccessTokenCredentials();
    TokenInfo token = null;
    if (tokenCredentials != null) {
      try {
        token = tokens
            .getTokenInfo(tokenCredentials.getToken());
      } catch (Exception e) {
        logger.error("Unable to retrieve token info", e);
      }
      logger.debug("Token: {}", token);
    }

    grant(info, principal,
        getPermissionFromPath(applicationId, "access"));

                /*
                 * grant(info, principal, getPermissionFromPath(applicationId,
                 * "get,put,post,delete", "/users/${user}",
                 * "/users/${user}/feed", "/users/${user}/activities",
                 * "/users/${user}/groups", "/users/${user}/following/*",
                 * "/users/${user}/following/user/*"));
                 */

    EntityManager em = emf.getEntityManager(applicationId);
    try {
      String appName = (String) em.getProperty(
          em.getApplicationRef(), "name");
      applicationSet.put(applicationId, appName);
      application = new ApplicationInfo(applicationId, appName);
    } catch (Exception e) {
    }

    try {
      Set<String> permissions = em.getRolePermissions("default");
      grant(info, principal, applicationId, permissions);
    } catch (Exception e) {
      logger.error("Unable to get user default role permissions",
          e);
    }

    UserInfo user = ((ApplicationUserPrincipal) principal)
        .getUser();
    try {
      Set<String> permissions = em.getUserPermissions(user
          .getUuid());
      grant(info, principal, applicationId, permissions);
    } catch (Exception e) {
      logger.error("Unable to get user permissions", e);
    }

    try {
      Set<String> rolenames = em.getUserRoles(user.getUuid());
      grantAppRoles(info, em, applicationId, token, principal, rolenames);
    } catch (Exception e) {
      logger.error("Unable to get user role permissions", e);
    }

    try {
      //TODO TN.  This is woefully inefficient, but temporary.  Introduce cassandra backed shiro caching so this only ever happens once.
      //See USERGRID-779 for details
      Results r = em.getCollection(new SimpleEntityRef(
          User.ENTITY_TYPE, user.getUuid()), "groups", null,
          1000, Results.Level.IDS, false);
      if (r != null) {

        Set<String> rolenames = new HashSet<String>();

        for (UUID groupId : r.getIds()) {

          Results roleResults = em.getCollection(new SimpleEntityRef(
              Group.ENTITY_TYPE, groupId), "roles", null,
              1000, Results.Level.CORE_PROPERTIES, false);

          for(Entity entity : roleResults.getEntities()){
            rolenames.add(entity.getName());
          }

        }


        grantAppRoles(info, em, applicationId, token, principal, rolenames);
      }

    } catch (Exception e) {
      logger.error("Unable to get user group role permissions", e);
    }

  }
}
