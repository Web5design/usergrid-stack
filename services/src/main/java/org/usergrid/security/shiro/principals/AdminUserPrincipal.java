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

import static org.usergrid.persistence.cassandra.CassandraService.MANAGEMENT_APPLICATION_ID;
import static org.usergrid.security.shiro.utils.SubjectUtils.getPermissionFromPath;

import org.apache.commons.lang.StringUtils;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.ManagementService;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.security.shiro.Realm;
import org.usergrid.security.shiro.UsergridRealm;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

import java.util.Map;
import java.util.UUID;

public class AdminUserPrincipal extends UserPrincipal {

  public AdminUserPrincipal(UserInfo user) {
    super(MANAGEMENT_APPLICATION_ID, user);
  }

  @Override
  public void populateAuthorizatioInfo(UsergridAuthorizationInfo info, UsergridRealm realm) throws Exception {
    // AdminUserPrincipals are through basic auth and sessions
    // They have access to organizations and organization
    // applications

    UserInfo user = getUser();

    final boolean superUserEnabled = realm.isSuperUserEnabled();
    final String superUser = realm.getSuperUser();

    if (superUserEnabled && (superUser != null)
        && superUser.equals(user.getUsername())) {
      // The system user has access to everything

      info.addRole(Realm.ROLE_SERVICE_ADMIN);
      info.addRole(Realm.ROLE_ORGANIZATION_ADMIN);
      info.addRole(Realm.ROLE_APPLICATION_ADMIN);
      info.addRole(Realm.ROLE_ADMIN_USER);

      info.addStringPermission("system:access");

      info.addStringPermission(
          "organizations:admin,access,get,put,post,delete:*");
      info.addStringPermission(
          "applications:admin,access,get,put,post,delete:*");
      info.addStringPermission(
          "organizations:admin,access,get,put,post,delete:*:/**");
      info.addStringPermission(
          "applications:admin,access,get,put,post,delete:*:/**");
      info.addStringPermission("users:access:*");

      info.addStringPermission(
          getPermissionFromPath(MANAGEMENT_APPLICATION_ID,
              "access"));

      info.addStringPermission(
          getPermissionFromPath(MANAGEMENT_APPLICATION_ID,
              "get,put,post,delete", "/**"));

    } else {

      // For regular service users, we find what organizations
      // they're associated with
      // An service user can be associated with multiple
      // organizations

      info.addStringPermission(
          getPermissionFromPath(MANAGEMENT_APPLICATION_ID,
              "access"));

      // admin users cannot access the management app directly
      // so open all permissions
      info.addStringPermission(
          getPermissionFromPath(MANAGEMENT_APPLICATION_ID,
              "get,put,post,delete", "/**"));

      info.addRole(Realm.ROLE_ADMIN_USER);

      final ManagementService management = realm.getManagement();


      Map<UUID, String> userOrganizations = management
          .getOrganizationsForAdminUser(user.getUuid());

      if (userOrganizations != null) {

        for (Map.Entry<UUID, String> entry : userOrganizations.entrySet()) {
          info.addStringPermission(
              new StringBuilder("organizations:admin,access,get,put,post,delete:").append(entry.getKey()).toString());

          info.addOrganizationInfo(new OrganizationInfo(entry.getKey(), entry.getValue()));
        }


        Map<UUID, String> userApplications = management
            .getApplicationsForOrganizations(userOrganizations.keySet());

        if (userApplications != null && !userApplications.isEmpty()) {

          StringBuilder permission = new StringBuilder("applications:admin,access,get,put,post,delete:");

          for (Map.Entry<UUID, String> entry : userApplications.entrySet()) {
            permission.append(entry.getKey()).append(",");

            info.addApplication(new ApplicationInfo(entry.getKey(), entry.getValue()));
          }

          //remove the extra comma
          permission.deleteCharAt(permission.length() - 1);

          info.addStringPermission(permission.toString());
        }

        info.addRole(Realm.ROLE_ORGANIZATION_ADMIN);
        info.addRole(Realm.ROLE_APPLICATION_ADMIN);
      }


    }
  }

}
