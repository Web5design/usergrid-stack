package org.usergrid.security.shiro.cache;


import java.util.UUID;

import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;


/** Simple interface for invalidating cache */
public interface CacheInvalidation
{


    /** Invalidate the organization cache */
    public void invalidateOrg( OrganizationInfo organizationInfo );

    /** Invalidate the organization cache */
    public void invalidateApplication( ApplicationInfo applicationInfo );

    /** Invalidate the guest access for the application */
    public void invalidateGuest( ApplicationInfo application );

    /** Invalidate the user for the given application and user */
    public void invalidateUser( UUID application, UserInfo user );
}
