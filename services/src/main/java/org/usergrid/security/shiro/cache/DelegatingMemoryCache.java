package org.usergrid.security.shiro.cache;


import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.security.shiro.principals.ApplicationGuestPrincipal;
import org.usergrid.security.shiro.principals.ApplicationPrincipal;
import org.usergrid.security.shiro.principals.ApplicationUserPrincipal;
import org.usergrid.security.shiro.principals.OrganizationPrincipal;
import org.usergrid.security.shiro.principals.PrincipalIdentifier;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.subject.SimplePrincipalCollection;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;


/**
 * Cache that holds results in a guava cache. If it doesn't exist in the memory cache, it will attempt to load it from
 * the delegate cache and then hold it in memory.  Ideally the delegate cache should have pre-calculated Roles and
 * permissions if present
 */
public class DelegatingMemoryCache
        implements Cache<SimplePrincipalCollection, UsergridAuthorizationInfo>, CacheInvalidation
{


    private static final Logger logger = LoggerFactory.getLogger( DelegatingMemoryCache.class );

    private final String realmName;

    private final Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate;

    private final com.google.common.cache.Cache<String, UsergridAuthorizationInfo> authCache;


    public DelegatingMemoryCache( int cacheSize, int expirationSeconds, String realmName,
                                  Cache<SimplePrincipalCollection, UsergridAuthorizationInfo> delegate )
    {

        this.realmName = realmName;
        this.delegate = delegate;


        authCache = CacheBuilder.newBuilder().maximumSize( cacheSize )
                                .expireAfterAccess( expirationSeconds, TimeUnit.SECONDS )
                                .removalListener( new CacheEvitionListener() ).build();
    }


    @Override
    public UsergridAuthorizationInfo get( SimplePrincipalCollection key ) throws CacheException
    {

        UsergridAuthorizationInfo authorizationInfo = authCache.getIfPresent( key );

        /**
         * Try to get it from the delegate
         */
        if ( authorizationInfo == null )
        {
            authorizationInfo = delegate.get( key );

            if ( authorizationInfo != null )
            {
                authCache.put( key.toString(), authorizationInfo );
            }
        }

        return authorizationInfo;
    }


    @Override
    public UsergridAuthorizationInfo put( SimplePrincipalCollection key, UsergridAuthorizationInfo value )
            throws CacheException
    {
        UsergridAuthorizationInfo authInfo = delegate.put( key, value );

        authCache.put( key.toString(), value );

        return authInfo;
    }


    @Override
    public UsergridAuthorizationInfo remove( SimplePrincipalCollection key ) throws CacheException
    {
        final String keyValue = key.toString();
        UsergridAuthorizationInfo localCached = authCache.getIfPresent( keyValue );

        if ( localCached != null )
        {
            authCache.invalidate( keyValue );
        }

        /**
         * We always remove from the delegate even if we're not holding the value locally.  We don't know how it's
         * implemented
         */
        delegate.remove( key );


        return localCached;
    }


    @Override
    public void clear() throws CacheException
    {
        delegate.clear();
    }


    @Override
    public int size()
    {
        return delegate.size();
    }


    @Override
    public Set<SimplePrincipalCollection> keys()
    {
        return delegate.keys();
    }


    @Override
    public Collection<UsergridAuthorizationInfo> values()
    {
        return delegate.values();
    }


    @Override
    public void invalidateOrg( OrganizationInfo organization )
    {
        final OrganizationPrincipal principal = new OrganizationPrincipal( organization );


        remove( getShiroPrincipal( principal ) );
    }


    @Override
    public void invalidateGuest( ApplicationInfo application )
    {
        final ApplicationGuestPrincipal principal = new ApplicationGuestPrincipal( application );


        remove( getShiroPrincipal( principal ) );
    }


    @Override
    public void invalidateUser( UUID application, UserInfo user )
    {
        final ApplicationUserPrincipal principal = new ApplicationUserPrincipal( application, user );

        remove( getShiroPrincipal( principal ) );
    }


    @Override
    public void invalidateApplication( ApplicationInfo applicationInfo )
    {
        final ApplicationPrincipal principal = new ApplicationPrincipal( applicationInfo );

        remove( getShiroPrincipal( principal ) );
    }


    private SimplePrincipalCollection getShiroPrincipal( PrincipalIdentifier id )
    {
        return new SimplePrincipalCollection( id, realmName );
    }


    private class CacheEvitionListener implements RemovalListener<String, UsergridAuthorizationInfo>
    {

        @Override
        public void onRemoval( RemovalNotification<String, UsergridAuthorizationInfo> notification )
        {
            logger.info( "Eviction {} from the local node cache", notification.getKey().toString() );
        }
    }
}
