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
import org.usergrid.management.UserInfo;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

import java.util.Map;
import java.util.UUID;

public class AdminUserPrincipal extends UserPrincipal {

	public AdminUserPrincipal(UserInfo user) {
		super(MANAGEMENT_APPLICATION_ID, user);
	}

  @Override
  public void populateAuthorizatioInfo(UsergridAuthorizationInfo info) {
    // AdminUserPrincipals are through basic auth and sessions
    // They have access to organizations and organization
    // applications

    UserInfo user = ((AdminUserPrincipal) principal).getUser();

    if (superUserEnabled && (superUser != null)
        && superUser.equals(user.getUsername())) {
      // The system user has access to everything

      role(info, principal, ROLE_SERVICE_ADMIN);
      role(info, principal, ROLE_ORGANIZATION_ADMIN);
      role(info, principal, ROLE_APPLICATION_ADMIN);
      role(info, principal, ROLE_ADMIN_USER);

      grant(info, principal, "system:access");

      grant(info, principal,
          "organizations:admin,access,get,put,post,delete:*");
      grant(info, principal,
          "applications:admin,access,get,put,post,delete:*");
      grant(info, principal,
          "organizations:admin,access,get,put,post,delete:*:/**");
      grant(info, principal,
          "applications:admin,access,get,put,post,delete:*:/**");
      grant(info, principal, "users:access:*");

      grant(info,
          principal,
          getPermissionFromPath(MANAGEMENT_APPLICATION_ID,
              "access"));

      grant(info,
          principal,
          getPermissionFromPath(MANAGEMENT_APPLICATION_ID,
              "get,put,post,delete", "/**"));

    } else {

      // For regular service users, we find what organizations
      // they're associated with
      // An service user can be associated with multiple
      // organizations

      grant(info,
          principal,
          getPermissionFromPath(MANAGEMENT_APPLICATION_ID,
              "access"));

      // admin users cannot access the management app directly
      // so open all permissions
      grant(info,
          principal,
          getPermissionFromPath(MANAGEMENT_APPLICATION_ID,
              "get,put,post,delete", "/**"));

      role(info, principal, ROLE_ADMIN_USER);

      try {

        Map<UUID, String> userOrganizations = management
            .getOrganizationsForAdminUser(user.getUuid());

        if (userOrganizations != null) {
          for (UUID id : userOrganizations.keySet()) {
            grant(info, principal,
                "organizations:admin,access,get,put,post,delete:"
                    + id);
          }
          organizationSet.putAll(userOrganizations);

          Map<UUID, String> userApplications = management
              .getApplicationsForOrganizations(userOrganizations
                  .keySet());
          if ((userApplications != null)
              && !userApplications.isEmpty()) {
            grant(info,
                principal,
                "applications:admin,access,get,put,post,delete:"
                    + StringUtils.join(
                    userApplications
                        .keySet(), ','));
            applicationSet.putAll(userApplications);
          }

          role(info, principal, ROLE_ORGANIZATION_ADMIN);
          role(info, principal, ROLE_APPLICATION_ADMIN);
        }

      } catch (Exception e) {
        logger.error(
            "Unable to construct admin user permissions", e);
      }
    }
  }

}
