package org.usergrid.security.shiro.cache;

import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.Test;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.utils.UUIDUtils;

import java.util.UUID;

import static junit.framework.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.*;

/**
 *
 * @author: tnine
 *
 */
public class DelegatingMemoryCacheTest {



  @Test
  public void testGet() throws Exception {


    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);
    CacheInvalidation invalidation = mock(CacheInvalidation.class);

    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, delegate, invalidation);

    SimplePrincipalCollection key = new SimplePrincipalCollection();
    UsergridAuthorizationInfo returned = new UsergridAuthorizationInfo();

    when(delegate.get(key)).thenReturn(returned);

    UsergridAuthorizationInfo auth = cache.get(key);

    assertSame(returned, auth);


  }


  @Test
  public void testGetNullDelegate() throws Exception {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);
    CacheInvalidation invalidation = mock(CacheInvalidation.class);

    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, delegate, invalidation);

    SimplePrincipalCollection key = new SimplePrincipalCollection();
    UsergridAuthorizationInfo returned = new UsergridAuthorizationInfo();

    when(delegate.get(key)).thenReturn(null);

    UsergridAuthorizationInfo auth = cache.get(key);

    assertNull(auth);

    //now return the value, assert it loads after a null
    when(delegate.get(key)).thenReturn(returned);

    auth = cache.get(key);

    assertSame(returned, auth);





  }


  @Test
  public void testPut(){

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);
    CacheInvalidation invalidation = mock(CacheInvalidation.class);

    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, delegate, invalidation);

    SimplePrincipalCollection key = new SimplePrincipalCollection();
    UsergridAuthorizationInfo returned = new UsergridAuthorizationInfo();


    UsergridAuthorizationInfo auth = cache.put(key, returned);

    verify(delegate).put(same(key), same(returned));
  }

  @Test
  public void testRemove() throws Exception {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);
    CacheInvalidation invalidation = mock(CacheInvalidation.class);

    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, delegate, invalidation);

    SimplePrincipalCollection key = new SimplePrincipalCollection();
    UsergridAuthorizationInfo returned = new UsergridAuthorizationInfo();


    cache.put(key, returned);

    verify(delegate).put(same(key), same(returned));


    cache.remove(key);

    verify(delegate).remove(same(key));

    UsergridAuthorizationInfo auth = cache.get(key);

    assertNull(auth);
  }


  @Test
  public void testInvalidateOrg() throws Exception {
    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);
    CacheInvalidation invalidation = mock(CacheInvalidation.class);

    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, delegate, invalidation);


    OrganizationInfo info = new OrganizationInfo(UUIDUtils.newTimeUUID(), "test");

    cache.invalidateOrg(info);

    verify(invalidation).invalidateOrg(same(info));
  }

  @Test
  public void testInvalidateApplication() throws Exception {
    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);
    CacheInvalidation invalidation = mock(CacheInvalidation.class);

    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, delegate, invalidation);


    ApplicationInfo info = new ApplicationInfo(UUIDUtils.newTimeUUID(), "org/test");

    cache.invalidateApplication(info);

    verify(invalidation).invalidateApplication(same(info));

  }

  @Test
  public void testInvalidateGuest() throws Exception {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);
    CacheInvalidation invalidation = mock(CacheInvalidation.class);

    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, delegate, invalidation);


    ApplicationInfo info = new ApplicationInfo(UUIDUtils.newTimeUUID(), "org/test");

    cache.invalidateGuest(info);

    verify(invalidation).invalidateGuest(same(info));

  }

  @Test
  public void testInvalidateUser() throws Exception {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);
    CacheInvalidation invalidation = mock(CacheInvalidation.class);

    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, delegate, invalidation);


    UUID applicationId = UUIDUtils.newTimeUUID();
    UserInfo info = new UserInfo(applicationId, UUIDUtils.newTimeUUID(), null, null, null, false, false, false, null);

    cache.invalidateUser(applicationId, info);

    verify(invalidation).invalidateUser(same(applicationId), same(info));

  }
}
