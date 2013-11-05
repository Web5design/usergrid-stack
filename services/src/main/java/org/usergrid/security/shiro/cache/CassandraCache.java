package org.usergrid.security.shiro.cache;

import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.subject.SimplePrincipalCollection;

import java.util.Collection;
import java.util.Set;

/**
 *
 * @author: tnine
 *
 */
public class CassandraCache implements Cache<SimplePrincipalCollection, SimpleAuthorizationInfo> {

  private static final int ONE_DAY = 60*60*24;

  private final String cacheName;

  private int ttl= ONE_DAY;

  public CassandraCache(String cacheName){
    this.cacheName = cacheName;
  }


  @Override
  public SimpleAuthorizationInfo get(SimplePrincipalCollection key) throws CacheException {
    return null;  //To change body of implemented methods use File | Settings | File Templates.
  }

  @Override
  public SimpleAuthorizationInfo put(SimplePrincipalCollection key, SimpleAuthorizationInfo value) throws CacheException {
    return null;  //To change body of implemented methods use File | Settings | File Templates.
  }

  @Override
  public SimpleAuthorizationInfo remove(SimplePrincipalCollection key) throws CacheException {
    return null;  //To change body of implemented methods use File | Settings | File Templates.
  }

  @Override
  public void clear() throws CacheException {
    throw new UnsupportedOperationException("Clear is not supported.  It requires too much iteration");
  }

  @Override
  public int size() {
    throw new UnsupportedOperationException("Size is not supported.  It requires too much iteration");
  }

  @Override
  public Set<SimplePrincipalCollection> keys() {
    throw new UnsupportedOperationException("keys is not supported.  It will most likely not load before OOM");
  }

  @Override
  public Collection<SimpleAuthorizationInfo> values() {
    throw new UnsupportedOperationException("values is not supported.  It will most likely not load before OOM");
  }
}
