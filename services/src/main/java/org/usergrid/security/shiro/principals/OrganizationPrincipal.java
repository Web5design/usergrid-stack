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

import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.security.shiro.Realm;
import org.usergrid.security.shiro.UsergridRealm;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

/**
 * OrganizationPrincipals are usually only through OAuth They have access to a single organization
 */
public class OrganizationPrincipal extends PrincipalIdentifier {

	final OrganizationInfo organization;

	public OrganizationPrincipal(OrganizationInfo organization) {
		this.organization = organization;
	}

	public OrganizationInfo getOrganization() {
		return organization;
	}

	@Override
	public String toString() {
    return new StringBuilder("org/").append(organization.getUuid().toString()).toString();
	}

  @Override
  public void populateAuthorizatioInfo(UsergridAuthorizationInfo info, UsergridRealm realm) throws Exception {

   info.addRole(Realm.ROLE_ORGANIZATION_ADMIN);
   info.addRole(Realm.ROLE_APPLICATION_ADMIN);
   info.addStringPermission(new StringBuilder("organizations:access:").append(organization.getUuid()).toString());

    info.addOrganizationInfo(organization);


    final Map<UUID, String> applications = realm.getManagement().getApplicationsForOrganization(organization.getUuid());

    if ((applications != null) && !applications.isEmpty()) {

      StringBuilder permissions = new StringBuilder("applications:admin,access,get,put,post,delete:");

      for(Map.Entry<UUID, String> entry: applications.entrySet()){
        permissions.append(entry.getKey()).append(",");

        info.addApplication(new ApplicationInfo(entry.getKey(), entry.getValue()));

      }

      permissions.deleteCharAt(permissions.length() -1);

      info.addStringPermission(permissions.toString());

    }
  }
}
