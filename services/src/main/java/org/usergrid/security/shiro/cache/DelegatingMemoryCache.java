package org.usergrid.security.shiro.cache;

import com.google.common.cache.*;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

import javax.annotation.PostConstruct;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Cache that holds results in a guava cache. If it doesn't exist in the memory cache, it will attempt to load
 * it from the delegate cache and then hold it in memory.  Ideally the delegate cache should have pre-calculated
 * Roles and permissions if present
 *
 * @author: tnine
 *
 */
public class DelegatingMemoryCache implements Cache<SimplePrincipalCollection, UsergridAuthorizationInfo>, CacheInvalidation {


  private static final Logger logger = LoggerFactory.getLogger(DelegatingMemoryCache.class);

  private final CacheInvalidation invalidation;
  private final Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate;

  private final com.google.common.cache.Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> authCache;



  public DelegatingMemoryCache(int cacheSize, int expirationSeconds, Cache<SimplePrincipalCollection,
      UsergridAuthorizationInfo> delegate, CacheInvalidation invalidation) {
    this.delegate = delegate;
    this.invalidation = invalidation;

    authCache = CacheBuilder.newBuilder()
        .maximumSize(cacheSize)
        .expireAfterAccess(expirationSeconds, TimeUnit.SECONDS)
        .removalListener(new CacheEvitionListener()).build();
  }

  @Override
  public UsergridAuthorizationInfo get(SimplePrincipalCollection key) throws CacheException {

    UsergridAuthorizationInfo authorizationInfo = authCache.getIfPresent(key);

    /**
     * Try to get it from the delegate
     */
    if(authorizationInfo == null){
      authorizationInfo = delegate.get(key);

      if(authorizationInfo != null){
        authCache.put(key, authorizationInfo);
      }

    }

    return authorizationInfo;
  }

  @Override
  public UsergridAuthorizationInfo put(SimplePrincipalCollection key, UsergridAuthorizationInfo value) throws CacheException {
    UsergridAuthorizationInfo authInfo = delegate.put(key, value);

    authCache.put(key, value);

    return authInfo;
  }

  @Override
  public UsergridAuthorizationInfo remove(SimplePrincipalCollection key) throws CacheException {
    UsergridAuthorizationInfo localCached  = authCache.getIfPresent(key);

    if(localCached != null){
      authCache.invalidate(key);
    }

    delegate.remove(key);


    return localCached;
  }

  @Override
  public void clear() throws CacheException {
    delegate.clear();
  }

  @Override
  public int size() {
    return delegate.size();
  }

  @Override
  public Set<SimplePrincipalCollection> keys() {
    return delegate.keys();
  }

  @Override
  public Collection<UsergridAuthorizationInfo> values() {
    return delegate.values();
  }

  @Override
  public void invalidateOrg(OrganizationInfo organizationInfo) {
    invalidation.invalidateOrg(organizationInfo);
  }

  @Override
  public void invalidateApplication(ApplicationInfo applicationInfo) {
    invalidation.invalidateApplication(applicationInfo);
  }

  @Override
  public void invalidateGuest(ApplicationInfo application) {
    invalidation.invalidateGuest(application);
  }

  @Override
  public void invalidateUser(UUID application, UserInfo user) {
    invalidation.invalidateUser(application, user);
  }


  private class CacheEvitionListener implements RemovalListener<SimplePrincipalCollection, UsergridAuthorizationInfo> {

    @Override
    public void onRemoval(RemovalNotification<SimplePrincipalCollection, UsergridAuthorizationInfo> notification) {
      logger.info("Eviction {} from the local node cache", notification.getKey().toString());
    }
  }


}
