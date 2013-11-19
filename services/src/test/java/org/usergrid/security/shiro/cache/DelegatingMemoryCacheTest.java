package org.usergrid.security.shiro.cache;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.Test;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.security.shiro.principals.ApplicationGuestPrincipal;
import org.usergrid.security.shiro.principals.ApplicationPrincipal;
import org.usergrid.security.shiro.principals.ApplicationUserPrincipal;
import org.usergrid.security.shiro.principals.PrincipalIdentifier;
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


    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, "test", delegate);

    SimplePrincipalCollection key = new SimplePrincipalCollection();
    UsergridAuthorizationInfo returned = new UsergridAuthorizationInfo();

    when(delegate.get(key)).thenReturn(returned);

    UsergridAuthorizationInfo auth = cache.get(key);

    assertSame(returned, auth);


  }


  @Test
  public void testGetNullDelegate() throws Exception {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);


    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, "test", delegate);

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
  public void testPut() {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);


    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, "test", delegate);

    SimplePrincipalCollection key = new SimplePrincipalCollection();
    UsergridAuthorizationInfo returned = new UsergridAuthorizationInfo();


    UsergridAuthorizationInfo auth = cache.put(key, returned);

    verify(delegate).put(same(key), same(returned));
  }

  @Test
  public void testRemove() throws Exception {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);


    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, "test", delegate);

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


    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, "test", delegate);


    OrganizationInfo info = new OrganizationInfo(UUIDUtils.newTimeUUID(), "test");

    cache.invalidateOrg(info);


  }

  @Test
  public void testInvalidateApplication() throws Exception {
    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);


    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, "test", delegate);

    UsergridAuthorizationInfo authInfo = new UsergridAuthorizationInfo();


    ApplicationInfo info = new ApplicationInfo(UUIDUtils.newTimeUUID(), "org/test");

    ApplicationPrincipal applicationUserPrincipal = new ApplicationPrincipal(info);

    SimplePrincipalCollection shiroPrincipal = createSimplePrincipal(applicationUserPrincipal, "test");

    cache.put(shiroPrincipal, authInfo);

    verify(delegate).put(same(shiroPrincipal), same(authInfo));

    //now invalidate it

    cache.invalidateApplication(info);

    verify(delegate).remove(eq(shiroPrincipal));

    //now check it's gone
    UsergridAuthorizationInfo returnedAuthInfo = cache.get(shiroPrincipal);

    assertNull(returnedAuthInfo);

  }

  @Test
  public void testInvalidateGuest() throws Exception {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);


    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, "test", delegate);

    UsergridAuthorizationInfo authInfo = new UsergridAuthorizationInfo();


    ApplicationInfo info = new ApplicationInfo(UUIDUtils.newTimeUUID(), "org/test");

    ApplicationGuestPrincipal applicationGuestPrincipal = new ApplicationGuestPrincipal(info);

    SimplePrincipalCollection shiroPrincipal = createSimplePrincipal(applicationGuestPrincipal, "test");

    cache.put(shiroPrincipal, authInfo);

    verify(delegate).put(same(shiroPrincipal), same(authInfo));

    //now invalidate it

    cache.invalidateGuest( info );

    verify(delegate).remove(eq( shiroPrincipal));

    //now check it's gone
    UsergridAuthorizationInfo returnedAuthInfo = cache.get(shiroPrincipal);

    assertNull(returnedAuthInfo);


  }

  @Test
  public void testInvalidateUser() throws Exception {

    Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate = mock(Cache.class);


    DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120, "test", delegate);


    UUID applicationId = UUIDUtils.newTimeUUID();
    UserInfo info = new UserInfo(applicationId, UUIDUtils.newTimeUUID(), null, null, null, false, false, false, null);

    UsergridAuthorizationInfo authInfo = new UsergridAuthorizationInfo();


    ApplicationUserPrincipal applicationUserPrincipal = new ApplicationUserPrincipal(applicationId, info);

    SimplePrincipalCollection shiroPrincipal = createSimplePrincipal(applicationUserPrincipal, "test");

    cache.put(shiroPrincipal, authInfo);

    verify(delegate).put(same(shiroPrincipal), same(authInfo));

    //now invalidate it

    cache.invalidateUser(applicationId, info);

    verify(delegate).remove(eq(shiroPrincipal));

    //now check it's gone
    UsergridAuthorizationInfo returnedAuthInfo = cache.get(shiroPrincipal);

    assertNull(returnedAuthInfo);


  }


  private SimplePrincipalCollection createSimplePrincipal(PrincipalIdentifier identifier, String realm) {

    return new SimplePrincipalCollection(identifier, realm);
  }
}
