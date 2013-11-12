package org.usergrid.security.shiro.auth;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.utils.MapUtils;

import java.util.*;

/**
 * Class to extend simple authorization info to keep track of which applicaions and which organizations users can participate it
 *
 * @author: tnine
 *
 */
public class UsergridAuthorizationInfo extends SimpleAuthorizationInfo {


  public Map<UUID, ApplicationInfo> applicationUUID = new HashMap<UUID, ApplicationInfo>();
  public Map<String, ApplicationInfo> applicationString = new HashMap<String, ApplicationInfo>();

  public Map<UUID, OrganizationInfo> organizationUUID = new HashMap<UUID, OrganizationInfo>();
  public Map<String, OrganizationInfo> organizationString = new HashMap<String, OrganizationInfo>();



  /**
   * Get the application by uuid
   * @param applicationId
   * @return
   */
  public ApplicationInfo getApplication(UUID applicationId){
    return applicationUUID.get(applicationId);
  }

  /**
   * Get the application by uuid
   * @param applicationName
   * @return
   */
  public ApplicationInfo getApplication(String applicationName){
    return applicationString.get(applicationName);
  }

  /**
   * Get all applications for this authorization info
   * @return
   */
  public Collection<ApplicationInfo> getApplications(){
    return applicationUUID.values();
  }


  /**
   * Add the application
   * @param info
   */
  public void addApplication(ApplicationInfo info){
    applicationUUID.put(info.getId(), info);
    applicationString.put(info.getName().toLowerCase(), info);
  }

  /**
   * Get organization by uuid
   * @param organizationid
   * @return
   */
  public OrganizationInfo getOrganization(UUID organizationid){
      return organizationUUID.get(organizationid);
  }

  /**
   * Get the organization by name
   * @param organizationName
   * @return
   */
  public OrganizationInfo getOrganization(String organizationName){
    return organizationString.get(organizationName);
  }


  /**
   * Get all applications for this authorization info
   * @return
   */
  public Collection<OrganizationInfo> getOrganizations(){
    return organizationUUID.values();
  }

  /**
   * Add the organization info
   * @param info
   */
  public void addOrganizationInfo(OrganizationInfo info){
    organizationUUID.put(info.getUuid(), info);
    organizationString.put(info.getName().toLowerCase(), info);
  }




}
