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

import java.util.UUID;

import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

public class ApplicationPrincipal extends PrincipalIdentifier {

	final ApplicationInfo application;

	public ApplicationPrincipal(ApplicationInfo application) {
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
		return String.format("app/%s", application.getId().toString());
	}

  @Override
  public void populateAuthorizatioInfo(UsergridAuthorizationInfo info) {
    // ApplicationPrincipal are usually only through OAuth
    // They have access to a single application

    role(info, principal, ROLE_APPLICATION_ADMIN);

    application = ((ApplicationPrincipal) principal)
        .getApplication();
    grant(info, principal,
        "applications:admin,access,get,put,post,delete:"
            + application.getId());
    applicationSet.put(application.getId(), application.getName());
  }
}
