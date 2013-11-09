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
import org.usergrid.management.OrganizationInfo;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

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
		return String.format("org/%s", organization.getUuid().toString());
	}

  @Override
  public void populateAuthorizatioInfo(UsergridAuthorizationInfo info) {
    // OrganizationPrincipals are usually only through OAuth
    // They have access to a single organization

    organization = ((OrganizationPrincipal) principal)
        .getOrganization();

    role(info, principal, ROLE_ORGANIZATION_ADMIN);
    role(info, principal, ROLE_APPLICATION_ADMIN);

    grant(info, principal,
        "organizations:access:" + organization.getUuid());
    organizationSet.put(organization.getUuid(),
        organization.getName());

    Map<UUID, String> applications = null;
    try {
      applications = management
          .getApplicationsForOrganization(organization
              .getUuid());
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    if ((applications != null) && !applications.isEmpty()) {
      grant(info,
          principal,
          "applications:admin,access,get,put,post,delete:"
              + StringUtils.join(applications.keySet(),
              ','));

      applicationSet.putAll(applications);
    }
  }
}
