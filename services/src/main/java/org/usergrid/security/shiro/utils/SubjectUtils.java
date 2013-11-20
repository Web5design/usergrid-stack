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
package org.usergrid.security.shiro.utils;


import java.util.Iterator;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.persistence.Identifier;
import org.usergrid.security.shiro.PrincipalCredentialsToken;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.security.shiro.principals.PrincipalIdentifier;
import org.usergrid.security.shiro.principals.UserPrincipal;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

import static org.usergrid.security.shiro.Realm.ROLE_APPLICATION_ADMIN;
import static org.usergrid.security.shiro.Realm.ROLE_APPLICATION_USER;
import static org.usergrid.security.shiro.Realm.ROLE_ORGANIZATION_ADMIN;
import static org.usergrid.security.shiro.Realm.ROLE_SERVICE_ADMIN;


public class SubjectUtils {

    private static final Logger logger = LoggerFactory.getLogger( SubjectUtils.class );


    public static boolean isAnonymous() {
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return true;
        }
        if ( !currentUser.isAuthenticated() && !currentUser.isRemembered() ) {
            return true;
        }
        return false;
    }




    public static boolean isPermittedAccessToOrganization( Identifier identifier ) {
        if ( isServiceAdmin() ) {
            return true;
        }
        OrganizationInfo organization = getOrganization( identifier );
        if ( organization == null ) {
            return false;
        }
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return false;
        }
        return currentUser.isPermitted( "organizations:access:" + organization.getUuid() );
    }


    public static OrganizationInfo getOrganization( Identifier identifier ) {
        if ( identifier == null ) {
            return null;
        }

        UsergridAuthorizationInfo authInfo = getAuthorizationInfo();

        if ( authInfo == null ) {
            return null;
        }

        if ( identifier.isName() ) {
            return authInfo.getOrganization( identifier.getName().toLowerCase() );
        }
        else if ( identifier.isUUID() ) {
            return authInfo.getOrganization( identifier.getUUID() );
        }


        return null;
    }


    public static OrganizationInfo getOrganization() {
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return null;
        }
        if ( !currentUser.hasRole( ROLE_ORGANIZATION_ADMIN ) ) {
            return null;
        }
        Session session = currentUser.getSession();
        OrganizationInfo organization = ( OrganizationInfo ) session.getAttribute( "organization" );
        return organization;
    }


    public static String getOrganizationName() {
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return null;
        }
        if ( !currentUser.hasRole( ROLE_ORGANIZATION_ADMIN ) ) {
            return null;
        }
        Session session = currentUser.getSession();
        OrganizationInfo organization = ( OrganizationInfo ) session.getAttribute( "organization" );
        if ( organization == null ) {
            return null;
        }
        return organization.getName();
    }


    public static boolean isApplicationAdmin() {
        if ( isServiceAdmin() ) {
            return true;
        }
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return false;
        }
        boolean admin = currentUser.hasRole( ROLE_APPLICATION_ADMIN );
        return admin;
    }


    public static boolean isPermittedAccessToApplication( Identifier identifier ) {
        if ( isServiceAdmin() ) {
            return true;
        }
        ApplicationInfo application = getApplication( identifier );
        if ( application == null ) {
            return false;
        }
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return false;
        }
        return currentUser.isPermitted( "applications:access:" + application.getId() );
    }


    public static boolean isApplicationAdmin( Identifier identifier ) {
        if ( isServiceAdmin() ) {
            return true;
        }
        ApplicationInfo application = getApplication( identifier );
        if ( application == null ) {
            return false;
        }
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return false;
        }
        return currentUser.isPermitted( "applications:admin:" + application.getId() );
    }


    public static ApplicationInfo getApplication( Identifier identifier ) {
        if ( identifier == null ) {
            return null;
        }
        if ( !isApplicationAdmin() && !isApplicationUser() ) {
            return null;
        }
        UsergridAuthorizationInfo info = getAuthorizationInfo();
        if ( info == null ) {
            return null;
        }
        if ( identifier.isName() ) {
            final String applicationName = identifier.getName().toLowerCase();
            return info.getApplication( applicationName );
        }
        else if ( identifier.isUUID() ) {
            final UUID applicationId = identifier.getUUID();
            return info.getApplication( applicationId );
        }

        return null;
    }


    /**
     *
     * @return
     */
    public static UsergridAuthorizationInfo getAuthorizationInfo() {


        Subject currentUser = getSubject();

        if ( currentUser == null ) {
            return null;
        }

        Iterator<PrincipalIdentifier> principals =
                currentUser.getPrincipals().byType( PrincipalIdentifier.class ).iterator();

        if ( !principals.hasNext() ) {
            return null;
        }


        return principals.next().getAuthorizationInfo();
    }


    public static boolean isServiceAdmin() {
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return false;
        }
        return currentUser.hasRole( ROLE_SERVICE_ADMIN );
    }


    public static boolean isApplicationUser() {
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return false;
        }
        return currentUser.hasRole( ROLE_APPLICATION_USER );
    }


    public static UserInfo getUser() {
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return null;
        }
        if ( !( currentUser.getPrincipal() instanceof UserPrincipal ) ) {
            return null;
        }
        UserPrincipal principal = ( UserPrincipal ) currentUser.getPrincipal();
        return principal.getUser();
    }


    public static UserInfo getAdminUser() {
        UserInfo user = getUser();
        if ( user == null ) {
            return null;
        }
        return user.isAdminUser() ? user : null;
    }


    public static UUID getSubjectUserId() {

        UserInfo info = getUser();
        if ( info == null ) {
            return null;
        }

        return info.getUuid();
    }





    public static boolean isUser( Identifier identifier ) {
        if ( identifier == null ) {
            return false;
        }
        UserInfo user = getUser();
        if ( user == null ) {
            return false;
        }
        if ( identifier.isUUID() ) {
            return user.getUuid().equals( identifier.getUUID() );
        }
        if ( identifier.isEmail() ) {
            return user.getEmail().equalsIgnoreCase( identifier.getEmail() );
        }
        if ( identifier.isName() ) {
            return user.getUsername().equals( identifier.getName() );
        }
        return false;
    }


    public static String getPermissionFromPath( UUID applicationId, String operations, String... paths ) {
        StringBuilder permission =
                new StringBuilder( "applications:" ).append( operations ).append( ":" ).append( applicationId );

        int size = paths.length;

        if ( size > 0 ) {
            permission.append( ":" );
        }

        for ( int i = 0; i < size; i++ ) {
            permission.append( paths[i] ).append( "," );
        }

        //we had paths, remove the last comma
        if ( size > 0 ) {
            permission.deleteCharAt( permission.length() - 1 );
        }

        return permission.toString();
    }


    public static Subject getSubject() {
        Subject currentUser = null;
        try {
            currentUser = SecurityUtils.getSubject();
        }
        catch ( UnavailableSecurityManagerException e ) {
            logger.error( "getSubject(): Attempt to use Shiro prior to initialization" );
        }
        return currentUser;
    }


    public static void checkPermission( String permission ) {
        Subject currentUser = getSubject();
        if ( currentUser == null ) {
            return;
        }
        try {
            currentUser.checkPermission( permission );
        }
        catch ( org.apache.shiro.authz.UnauthenticatedException e ) {
            logger.error( "checkPermission(): Subject is anonymous" );
        }
    }


    public static void loginApplicationGuest( ApplicationInfo application ) {
        if ( application == null ) {
            logger.error( "loginApplicationGuest(): Null application" );
            return;
        }
        if ( isAnonymous() ) {
            Subject subject = SubjectUtils.getSubject();
            PrincipalCredentialsToken token =
                    PrincipalCredentialsToken.getGuestCredentialsFromApplicationInfo( application );
            subject.login( token );
        }
        else {
            logger.error( "loginApplicationGuest(): Logging in non-anonymous user as guest not allowed" );
        }
    }
}
