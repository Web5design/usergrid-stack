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

import org.apache.shiro.authz.SimpleAuthorizationInfo;



import org.usergrid.management.UserInfo;
import org.usergrid.persistence.EntityManager;
import org.usergrid.persistence.entities.Role;
import org.usergrid.security.shiro.Realm;
import org.usergrid.security.shiro.UsergridRealm;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.security.shiro.credentials.AccessTokenCredentials;
import org.usergrid.security.tokens.TokenInfo;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.usergrid.utils.StringUtils.stringOrSubstringAfterFirst;
import static org.usergrid.utils.StringUtils.stringOrSubstringBeforeFirst;


public abstract class PrincipalIdentifier {



  private AccessTokenCredentials accessTokenCredentials;
  private UsergridAuthorizationInfo authorizationInfo;



    public boolean isActivated() {
        return true;
    }

  public boolean isDisabled() {
 		return false;
 	}

  public AccessTokenCredentials getAccessTokenCredentials() {
    return accessTokenCredentials;
  }

  public void setAccessTokenCredentials(AccessTokenCredentials accessTokenCredentials) {
    this.accessTokenCredentials = accessTokenCredentials;
  }

  public UsergridAuthorizationInfo getAuthorizationInfo() {
    return authorizationInfo;
  }

  public void setAuthorizationInfo(UsergridAuthorizationInfo authorizationInfo) {
    this.authorizationInfo = authorizationInfo;
  }

  /**
   * Grant all permissions for the role names on this application
   * @param info
   * @param em
   * @param applicationId
   * @param token
   * @param rolenames
   * @throws Exception
   */
  protected void grantAppRoles(UsergridAuthorizationInfo info, EntityManager em, UUID applicationId,  TokenInfo token, Set<String> rolenames) throws Exception{
    Map<String, Role> app_roles = em
        .getRolesWithTitles(rolenames);

    for (String rolename : rolenames) {
      if ((app_roles != null) && (token != null)) {
        Role role = app_roles.get(rolename);
        if ((role != null)
            && (role.getInactivity() > 0)
            && (token.getInactive() > role
            .getInactivity())) {
          continue;
        }
      }
      Set<String> permissions = em
          .getRolePermissions(rolename);
      grant(info, applicationId, permissions);

      final String role = new StringBuilder("application-role:").append(applicationId).append(":").append(rolename).toString();

      info.addRole(role);

    }
  }



  protected void grant(UsergridAuthorizationInfo info,  UUID applicationId,
                            Set<String> permissions) {
    if (permissions != null) {
      for (String permission : permissions) {
        if (isNotBlank(permission)) {
          String operations = "*";
          if (permission.indexOf(':') != -1) {
            operations = stringOrSubstringBeforeFirst(permission,
                ':');
          }
          if (isBlank(operations)) {
            operations = "*";
          }
          permission = stringOrSubstringAfterFirst(permission, ':');
          permission =  new StringBuilder("applications:").append(operations).append(":").append(applicationId).append(":").append(permission).toString();
          info.addStringPermission(permission);
        }
      }
    }
  }
  /**
   * Generate the authorization info for this principal
   *
   * @param info The information object that should be populated
   * @param realm The realm requesting the populate operation
   *
   * @return
   */
  public abstract void populateAuthorizatioInfo(UsergridAuthorizationInfo info, UsergridRealm realm) throws Exception;


}
