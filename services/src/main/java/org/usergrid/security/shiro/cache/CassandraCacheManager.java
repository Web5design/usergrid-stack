package org.usergrid.security.shiro.cache;

import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.subject.SimplePrincipalCollection;

/**
 *
 * Simple cache manager to return and maintain pointer to all cache managers for clearing
 * @author: tnine
 *
 */
public class CassandraCacheManager implements CacheManager {

  @Override
  public Cache<SimplePrincipalCollection, SimpleAuthorizationInfo> getCache(String name) throws CacheException {
     return new CassandraCache(name);
  }
}
