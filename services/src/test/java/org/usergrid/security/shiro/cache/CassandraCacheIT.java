package org.usergrid.security.shiro.cache;

import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.usergrid.ServiceITSetup;
import org.usergrid.ServiceITSetupImpl;
import org.usergrid.ServiceITSuite;
import org.usergrid.cassandra.ClearShiroSubject;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.security.shiro.principals.*;
import org.usergrid.utils.UUIDUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.fail;

/**
 *
 * @author: tnine
 *
 */
public class CassandraCacheIT {


  @Rule
  public ClearShiroSubject clearShiroSubject = new ClearShiroSubject();

  @ClassRule
  public static ServiceITSetup setup = new ServiceITSetupImpl( ServiceITSuite.cassandraResource );





  @Test
  public void storeAndLoadUserPrincipal(){

    UserInfo userInfo = new UserInfo(UUIDUtils.newTimeUUID(), UUIDUtils.newTimeUUID(), "test", "test", "test@usergrid.org", true, true, false, null);

    ApplicationUserPrincipal applicationUserPrincipal = new ApplicationUserPrincipal(userInfo.getApplicationId(), userInfo);

    storeAndLoad(applicationUserPrincipal);
  }

  @Test
  public void storeAndLoadAdminPrincipal(){

    UserInfo userInfo = new UserInfo(UUIDUtils.newTimeUUID(), UUIDUtils.newTimeUUID(), "test", "test", "test@usergrid.org", true, true, false, null);


    AdminUserPrincipal adminUser = new AdminUserPrincipal(userInfo) ;

    storeAndLoad(adminUser);
  }


  @Test
  public void storeAndLoadGuestPrincipal(){

    ApplicationInfo appInfo = new ApplicationInfo(UUIDUtils.newTimeUUID(), "test");
    ApplicationGuestPrincipal guest = new ApplicationGuestPrincipal(appInfo);

    storeAndLoad(guest);
  }


  @Test
  public void storeAndLoadApplicationPrincipal(){

    ApplicationInfo appInfo = new ApplicationInfo(UUIDUtils.newTimeUUID(), "test");
    ApplicationPrincipal principal = new ApplicationPrincipal(appInfo);

    storeAndLoad(principal);
  }

  @Test
  public void storeAndLoadOrganizationPrincipal(){

    OrganizationInfo info = new OrganizationInfo(UUIDUtils.newTimeUUID(), "test");
    OrganizationPrincipal orgPrincipal = new OrganizationPrincipal(info);
    storeAndLoad(orgPrincipal);
  }


  private void storeAndLoad(PrincipalIdentifier principalIdentifier){
    String realm = "test";
    CassandraCacheManager manager = setup.getCacheManager();


    SimplePrincipalCollection principal = createSimplePrincipal(principalIdentifier, realm);



    Cache<SimplePrincipalCollection,UsergridAuthorizationInfo> cache = manager.getCache(realm);

    SimpleAuthorizationInfo authorizationInfo = cache.get(principal);

    assertNull(authorizationInfo);

    //now store it

    UsergridAuthorizationInfo storedAuthInfo = generateAuthInfo();

    /**
     * Store it into the cache
     */
    UsergridAuthorizationInfo storedOnCache = cache.put(principal, storedAuthInfo);

    assertEqualsInternal(storedAuthInfo, storedOnCache);


    //now get it back from the cache
    UsergridAuthorizationInfo returnedFromCache = cache.get(principal);

    assertEqualsInternal(storedAuthInfo, returnedFromCache);


    //now delete it
    returnedFromCache = cache.remove(principal);

    assertEqualsInternal(storedAuthInfo, returnedFromCache);

    returnedFromCache = cache.get(principal);

    assertNull(returnedFromCache);
  }







  @Test
  public void realmPartitioningUserPrincipal(){

    UserInfo userInfo = new UserInfo(UUIDUtils.newTimeUUID(), UUIDUtils.newTimeUUID(), "test", "test", "test@usergrid.org", true, true, false, null);

    ApplicationUserPrincipal applicationUserPrincipal = new ApplicationUserPrincipal(userInfo.getApplicationId(), userInfo);

    realmPartitioning(applicationUserPrincipal);
  }

  @Test
  public void realmPartitioningAdminPrincipal(){

    UserInfo userInfo = new UserInfo(UUIDUtils.newTimeUUID(), UUIDUtils.newTimeUUID(), "test", "test", "test@usergrid.org", true, true, false, null);


    AdminUserPrincipal adminUser = new AdminUserPrincipal(userInfo) ;

    realmPartitioning(adminUser);
  }


  @Test
  public void realmPartitioningGuestPrincipal(){

    ApplicationInfo appInfo = new ApplicationInfo(UUIDUtils.newTimeUUID(), "test");
    ApplicationGuestPrincipal guest = new ApplicationGuestPrincipal(appInfo);

    realmPartitioning(guest);
  }


  @Test
  public void realmPartitioningApplicationPrincipal(){

    ApplicationInfo appInfo = new ApplicationInfo(UUIDUtils.newTimeUUID(), "test");
    ApplicationPrincipal principal = new ApplicationPrincipal(appInfo);

    realmPartitioning(principal);
  }

  @Test
  public void realmPartitioningOrganizationPrincipal(){

    OrganizationInfo info = new OrganizationInfo(UUIDUtils.newTimeUUID(), "test");
    OrganizationPrincipal orgPrincipal = new OrganizationPrincipal(info);
    realmPartitioning(orgPrincipal);
  }



  /**
   * Test to ensure that realms are stored seperately
   */
  public void realmPartitioning(PrincipalIdentifier principalIdentifier){
    String realm = "test";
    CassandraCacheManager manager = setup.getCacheManager();

    SimplePrincipalCollection principal = createSimplePrincipal(principalIdentifier, realm);



    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> cache = manager.getCache(realm);

    UsergridAuthorizationInfo authorizationInfo = cache.get(principal);

    assertNull(authorizationInfo);

    //now store it
    UsergridAuthorizationInfo storedAuthInfo = generateAuthInfo();



    /**
     * Store it into the cache
     */
    UsergridAuthorizationInfo storedOnCache = cache.put(principal, storedAuthInfo);

    assertEqualsInternal(storedAuthInfo, storedOnCache);


    //now get it back from the cache
    UsergridAuthorizationInfo returnedFromCache = cache.get(principal);

    assertEqualsInternal(storedAuthInfo, returnedFromCache);


    //now load the same principal, but from another realm, we should not get this back since the realms are different

    String otherRealm = "otherrealm";

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> otherCache = manager.getCache(otherRealm);


    SimplePrincipalCollection otherPrincipal = createSimplePrincipal(principalIdentifier, otherRealm);


    SimpleAuthorizationInfo otherRealmReturned = otherCache.get(otherPrincipal);

    assertNull(otherRealmReturned);
  }

  private void assertEqualsInternal(UsergridAuthorizationInfo expected, UsergridAuthorizationInfo returned){

    if(expected == null && returned == null){
      return;
    }

    if(expected == null && returned != null){
      fail("returned is not null and expected is");
    }

    if( expected != null && returned == null){
      fail("excepted was not null, but returned is");
    }


    Set<String> expectedRoles = new HashSet<String>(expected.getRoles());
    Set<String> returnedRoles = new HashSet<String>(returned.getRoles());

    expectedRoles.removeAll(returned.getRoles());
    returnedRoles.removeAll(expected.getRoles());

    assertEquals("Not all roles in expected were in the returned", 0, expectedRoles.size());
    assertEquals("Not all roles in returned were in the expected", 0, returnedRoles.size());



    Set<String> expectedPermissions = new HashSet<String>(expected.getStringPermissions());
    Set<String> returnedPermissions = new HashSet<String>(returned.getStringPermissions());

    expectedPermissions.removeAll(returned.getStringPermissions());
    returnedPermissions.removeAll(expected.getStringPermissions());

    assertEquals("Not all permissions in expected were in the returned", 0, expectedPermissions.size());
    assertEquals("Not all permissions in returned were in the expected", 0, returnedPermissions.size());


    Set<ApplicationInfo> expectedApps = new HashSet<ApplicationInfo>(expected.getApplications());
    Set<ApplicationInfo> returnedApps = new HashSet<ApplicationInfo>(returned.getApplications());

    expectedApps.removeAll(returned.getApplications());
    returnedApps.removeAll(expected.getApplications());

    assertEquals("Not all applications in expected were in the returned", 0, expectedApps.size());
    assertEquals("Not all applications in returned were in the expected", 0, returnedApps.size());

    Set<OrganizationInfo> expectedOrgs = new HashSet<OrganizationInfo>(expected.getOrganizations());
    Set<OrganizationInfo> returnedOrgs = new HashSet<OrganizationInfo>(returned.getOrganizations());

    expectedOrgs.removeAll(returned.getOrganizations());
    returnedOrgs.removeAll(expected.getOrganizations());

    assertEquals("Not all organization in expected were in the returned", 0, expectedOrgs.size());
    assertEquals("Not all organizations in returned were in the expected", 0, returnedOrgs.size());




  }



  @Test
  public void serviceRevokeUserPrincipal(){

    UserInfo userInfo = new UserInfo(UUIDUtils.newTimeUUID(), UUIDUtils.newTimeUUID(), "test", "test", "test@usergrid.org", true, true, false, null);

    ApplicationUserPrincipal applicationUserPrincipal = new ApplicationUserPrincipal(userInfo.getApplicationId(), userInfo);

    serviceRevokeWrite(applicationUserPrincipal);


    CassandraCacheManager manager = setup.getCacheManager();

    manager.invalidateUser(applicationUserPrincipal.getApplicationId(), userInfo);

    serviceRevokeVerify(applicationUserPrincipal);

  }

  @Test
  public void serviceRevokeAdminPrincipal(){

    UserInfo userInfo = new UserInfo(UUIDUtils.newTimeUUID(), UUIDUtils.newTimeUUID(), "test", "test", "test@usergrid.org", true, true, false, null);


    AdminUserPrincipal adminUser = new AdminUserPrincipal(userInfo) ;

    serviceRevokeWrite(adminUser);


    CassandraCacheManager manager = setup.getCacheManager();

    manager.invalidateUser(adminUser.getApplicationId(), userInfo);

    serviceRevokeVerify(adminUser);
  }


  @Test
  public void serviceRevokeGuestPrincipal(){

    ApplicationInfo appInfo = new ApplicationInfo(UUIDUtils.newTimeUUID(), "test");
    ApplicationGuestPrincipal guest = new ApplicationGuestPrincipal(appInfo);

    serviceRevokeWrite(guest);

    CassandraCacheManager manager = setup.getCacheManager();

    manager.invalidateGuest(appInfo);

    serviceRevokeVerify(guest);
  }


  @Test
  public void serviceRevokeApplicationPrincipal(){

    ApplicationInfo appInfo = new ApplicationInfo(UUIDUtils.newTimeUUID(), "test");
    ApplicationPrincipal principal = new ApplicationPrincipal(appInfo);

    serviceRevokeWrite(principal);

    CassandraCacheManager manager = setup.getCacheManager();

    manager.invalidateApplication(appInfo);

    serviceRevokeVerify(principal);
  }

  @Test
  public void serviceRevokeOrganizationPrincipal(){

    OrganizationInfo info = new OrganizationInfo(UUIDUtils.newTimeUUID(), "test");
    OrganizationPrincipal orgPrincipal = new OrganizationPrincipal(info);
    serviceRevokeWrite(orgPrincipal);

    CassandraCacheManager manager = setup.getCacheManager();

    manager.invalidateOrg(info);

    serviceRevokeVerify(orgPrincipal);
  }


  private void serviceRevokeWrite(PrincipalIdentifier principalIdentifier){
    String realm = "test";
    CassandraCacheManager manager = setup.getCacheManager();


    SimplePrincipalCollection principal = createSimplePrincipal(principalIdentifier, realm);



    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> cache = manager.getCache(realm);

    SimpleAuthorizationInfo authorizationInfo = cache.get(principal);

    assertNull(authorizationInfo);

    //now store it

    UsergridAuthorizationInfo storedAuthInfo = generateAuthInfo();

    /**
     * Store it into the cache
     */
    UsergridAuthorizationInfo storedOnCache = cache.put(principal, storedAuthInfo);

    assertEqualsInternal(storedAuthInfo, storedOnCache);


    //now get it back from the cache
    UsergridAuthorizationInfo returnedFromCache = cache.get(principal);

    assertEqualsInternal(storedAuthInfo, returnedFromCache);


  }

  private void serviceRevokeVerify(PrincipalIdentifier principalIdentifier){

    String realm = "test";
    CassandraCacheManager manager = setup.getCacheManager();


    SimplePrincipalCollection principal = createSimplePrincipal(principalIdentifier, realm);



    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> cache = manager.getCache(realm);

    SimpleAuthorizationInfo returnedFromCache = cache.get(principal);

    assertNull(returnedFromCache);
  }





  private SimplePrincipalCollection createSimplePrincipal(PrincipalIdentifier identifier, String realm){

    return new SimplePrincipalCollection(identifier, realm);
  }

  private UsergridAuthorizationInfo generateAuthInfo(){

    UsergridAuthorizationInfo storedAuthInfo = new UsergridAuthorizationInfo();
    storedAuthInfo.addRole("appuser");
    storedAuthInfo.addRole("user");
    storedAuthInfo.addStringPermission("GET,PUT,POST,DELETE:/groups/oss/**");
    storedAuthInfo.addStringPermission("GET:/groups/**");
    storedAuthInfo.addStringPermission("GET,PUT,POST,DELETE::/users/me/**");

    ApplicationInfo app1 = new ApplicationInfo(UUIDUtils.newTimeUUID(), "testorg1/testapp1");
    ApplicationInfo app2 = new ApplicationInfo(UUIDUtils.newTimeUUID(), "testorg2/testapp2");

    storedAuthInfo.addApplication(app1);
    storedAuthInfo.addApplication(app2);


    OrganizationInfo org1 = new OrganizationInfo(UUIDUtils.newTimeUUID(), "testorg1");
    OrganizationInfo org2 = new OrganizationInfo(UUIDUtils.newTimeUUID(), "testorg2");

    storedAuthInfo.addOrganizationInfo(org1);
    storedAuthInfo.addOrganizationInfo(org2);

    return storedAuthInfo;
  }
}
