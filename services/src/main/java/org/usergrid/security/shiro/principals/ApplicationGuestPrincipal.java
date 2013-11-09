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

import java.util.Set;
import java.util.UUID;

import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.persistence.EntityManager;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

import static org.usergrid.security.shiro.utils.SubjectUtils.getPermissionFromPath;

public class ApplicationGuestPrincipal extends PrincipalIdentifier {

	final ApplicationInfo application;

	public ApplicationGuestPrincipal(ApplicationInfo application) {
		this.application = application;
	}

	public UUID getApplicationId() {
		return application.getId();
	}

	public ApplicationInfo getApplication() {
		return application;
	}

	@Override
	public String toString() {
		return String.format("guestuser/%s", application.getId().toString());
	}

  @Override
  public void populateAuthorizatioInfo(UsergridAuthorizationInfo info) {
    role(info, principal, ROLE_APPLICATION_USER);

    UUID applicationId = ((ApplicationGuestPrincipal) principal)
        .getApplicationId();

    EntityManager em = emf.getEntityManager(applicationId);
    try {
      String appName = (String) em.getProperty(
          em.getApplicationRef(), "name");
      applicationSet.put(applicationId, appName);
      application = new ApplicationInfo(applicationId, appName);
    } catch (Exception e) {
    }

    grant(info, principal,
        getPermissionFromPath(applicationId, "access"));

    try {
      Set<String> permissions = em.getRolePermissions("guest");
      grant(info, principal, applicationId, permissions);
    } catch (Exception e) {
      logger.error("Unable to get user default role permissions",
          e);
    }
  }
}
