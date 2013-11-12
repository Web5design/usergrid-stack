package org.usergrid.security.shiro.cache;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.persistence.cassandra.CassandraService;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

import java.util.UUID;
import java.util.concurrent.ExecutionException;

/**
 *
 * Cache manager to return and maintain pointer to all cache managers for clearing.
 *
 * Creates an in memory cache, that will then delegate to cassandra for pre calculated values
 * Reading the pre-calculated values from cassandra and caching locally is significantly more efficient
 * than re calculating effective permissions.  Service logic that affects permissions should invoke the CacheInvalidation
 * interface to remove calculated permissions from the caches
 *
 * @author: tnine
 *
 */
public class CassandraCacheManager implements CacheManager, CacheInvalidation {

  private static final Logger logger = LoggerFactory.getLogger(CassandraCacheManager.class);

  private CassandraService cassandraService;


  /**
   * Cache of all realm cassandra caches.  This way we can invalidate the cache for each realm when permissions are updated
   */
  private LoadingCache<String, DelegatingMemoryCache > cassandraCache = CacheBuilder.newBuilder()
      .maximumSize(1000)
      .build(
          new CacheLoader<String, DelegatingMemoryCache>() {

            @Override
            public DelegatingMemoryCache load(String name) throws Exception {
              CassandraCache cassCache = new CassandraCache(cassandraService, name);
              DelegatingMemoryCache cache = new DelegatingMemoryCache(1000, 120,cassCache, cassCache );
              return cache;
            }
          });


  @Override
  public Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> getCache(String name) throws CacheException {
    try {
      return cassandraCache.get(name);
    } catch (ExecutionException e) {
      logger.error("Unable to access cache", e);
      throw new CacheException("Unable to access cache", e);
    }
  }


  @Override
  public void invalidateOrg(final OrganizationInfo organizationInfo) {
    runOnCache(new CacheOperation(){

      @Override
      public void doInCache(DelegatingMemoryCache cache) {
        cache.invalidateOrg(organizationInfo);
      }
    });


  }

  @Override
  public void invalidateApplication(final ApplicationInfo applicationInfo) {
    runOnCache(new CacheOperation(){

      @Override
      public void doInCache(DelegatingMemoryCache cache) {
        cache.invalidateApplication(applicationInfo);
      }
    });
  }

  @Override
  public void invalidateGuest(final ApplicationInfo application) {
    runOnCache(new CacheOperation(){

      @Override
      public void doInCache(DelegatingMemoryCache cache) {
        cache.invalidateGuest(application);
      }
    });
  }

  @Override
  public void invalidateUser(final UUID application, final UserInfo user) {
    runOnCache(new CacheOperation(){

      @Override
      public void doInCache(DelegatingMemoryCache cache) {
        cache.invalidateUser(application, user);
      }
    });
  }

  private void runOnCache(CacheOperation cacheOperation){
    for (String key: cassandraCache.asMap().keySet()){
      try {
        cacheOperation.doInCache(cassandraCache.get(key));
      } catch (ExecutionException e) {
        logger.error("Unable to get cache", e);
        throw new RuntimeException("Unable to get cache", e);
      }
    }
  }


  @Autowired
  public void setCassandraService(CassandraService cassandraService) {
    this.cassandraService = cassandraService;
  }





  private interface CacheOperation{

    /**
     * Perform the operation in the cache
     * @param cache
     */
    public void doInCache(DelegatingMemoryCache cache);

  }


}
