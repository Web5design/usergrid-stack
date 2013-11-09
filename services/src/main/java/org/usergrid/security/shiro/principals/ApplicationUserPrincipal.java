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
import org.usergrid.security.shiro.Realm;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.security.shiro.credentials.AccessTokenCredentials;
import org.usergrid.security.tokens.TokenInfo;

import static org.usergrid.security.shiro.utils.SubjectUtils.getPermissionFromPath;

public class ApplicationUserPrincipal extends UserPrincipal {

  public ApplicationUserPrincipal(UUID applicationId, UserInfo user) {
    super(applicationId, user);
  }


  @Override
  public void populateAuthorizatioInfo(UsergridAuthorizationInfo info, Realm realm) throws Exception {

    info.addRole(Realm.ROLE_APPLICATION_USER);

//
//    TODO T.N. I don't think we need this anymore.  A token should already be present to get this far


    info.addStringPermission(getPermissionFromPath(applicationId, "access"));

                /*
                 * grant(info, principal, getPermissionFromPath(applicationId,
                 * "get,put,post,delete", "/users/${user}",
                 * "/users/${user}/feed", "/users/${user}/activities",
                 * "/users/${user}/groups", "/users/${user}/following/*",
                 * "/users/${user}/following/user/*"));
                 */

//    TODO T.N. not sure if this is obscelete
//    EntityManager em = emf.getEntityManager(applicationId);
//    try {
//      String appName = (String) em.getProperty(
//          em.getApplicationRef(), "name");
//      applicationSet.put(applicationId, appName);
//      application = new ApplicationInfo(applicationId, appName);
//    } catch (Exception e) {
//    }


    final EntityManager em = realm.getEmf().getEntityManager(applicationId);


    final Set<String> permissions = em.getRolePermissions("default");

    grant(info, applicationId, permissions);


    final Set<String> userPermissions = em.getUserPermissions(user.getUuid());

    grant(info, applicationId, userPermissions);


    final AccessTokenCredentials tokenCredentials = getAccessTokenCredentials();

    TokenInfo token = null;

    if (tokenCredentials != null) {

      token = realm.getTokens().getTokenInfo(tokenCredentials.getToken());
    }

    final Set<String> userRoleNames = em.getUserRoles(user.getUuid());
    grantAppRoles(info, em, applicationId, token, userRoleNames);


    Results r = em.getCollection(new SimpleEntityRef(
        User.ENTITY_TYPE, user.getUuid()), "groups", null,
        1000, Results.Level.IDS, false);
    if (r != null) {

      final Set<String> rolenames = new HashSet<String>();

      for (UUID groupId : r.getIds()) {

        Results roleResults = em.getCollection(new SimpleEntityRef(
            Group.ENTITY_TYPE, groupId), "roles", null,
            1000, Results.Level.CORE_PROPERTIES, false);

        for (Entity entity : roleResults.getEntities()) {
          rolenames.add(entity.getName());
        }

      }


      grantAppRoles(info, em, applicationId, token, rolenames);
    }


  }
}
