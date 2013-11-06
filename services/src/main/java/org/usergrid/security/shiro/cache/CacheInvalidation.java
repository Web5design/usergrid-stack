package org.usergrid.security.shiro.cache;

import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;

import java.util.UUID;

/**
 *
 * Simple interface for invalidating cache
 *
 * @author: tnine
 *
 */
public interface CacheInvalidation {


  /**
   * Invalidate the organization cache
   * @param organizationInfo
   */
  public void invalidateOrg(OrganizationInfo organizationInfo);

  /**
   * Invalidate the organization cache
   * @param applicationInfo
   */
  public void invalidateApplication(ApplicationInfo applicationInfo);

  /**
   * Invalidate the guest access for the application
   * @param application
   */
  public void invalidateGuest(ApplicationInfo application);

  /**
   * Invalidate the user for the given application and user
   * @param application
   * @param user
   */
  public void invalidateUser(UUID application, UserInfo user);
}
