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

import org.usergrid.management.ApplicationInfo;
import org.usergrid.persistence.EntityManager;
import org.usergrid.security.shiro.Realm;
import org.usergrid.security.shiro.UsergridRealm;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

import static org.usergrid.security.shiro.utils.SubjectUtils.getPermissionFromPath;


public class ApplicationGuestPrincipal extends PrincipalIdentifier
{


    final ApplicationInfo application;


    public ApplicationGuestPrincipal( ApplicationInfo application )
    {
        this.application = application;
    }


    public UUID getApplicationId()
    {
        return application.getId();
    }


    public ApplicationInfo getApplication()
    {
        return application;
    }


    @Override
    public String toString()
    {
        return new StringBuilder( "guestuser/" ).append( application.getId() ).toString();
    }


    @Override
    public void populateAuthorizatioInfo( UsergridAuthorizationInfo info, UsergridRealm realm ) throws Exception
    {

        info.addRole( Realm.ROLE_APPLICATION_USER );


        final UUID applicationId = getApplicationId();

        final EntityManager em = realm.getEmf().getEntityManager( applicationId );

        // TODO T.N Do we even need this any more?
        //    try {
        //      String appName = (String) em.getProperty(em.getApplicationRef(), "name");
        //      applicationSet.put(applicationId, appName);
        //      application = new ApplicationInfo(applicationId, appName);
        //    } catch (Exception e) {
        //    }

        info.addStringPermission( getPermissionFromPath( applicationId, "access" ) );

        Set<String> permissions = em.getRolePermissions( "guest" );

        grant( info, applicationId, permissions );

        info.addApplication( application );
    }
}
