package org.usergrid.security.shiro.cache;


import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.persistence.cassandra.CassandraService;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.subject.SimplePrincipalCollection;

import me.prettyprint.cassandra.serializers.BytesArraySerializer;
import me.prettyprint.cassandra.serializers.DynamicCompositeSerializer;
import me.prettyprint.cassandra.serializers.StringSerializer;
import me.prettyprint.cassandra.serializers.UUIDSerializer;
import me.prettyprint.hector.api.Keyspace;
import me.prettyprint.hector.api.beans.AbstractComposite;
import me.prettyprint.hector.api.beans.ColumnSlice;
import me.prettyprint.hector.api.beans.DynamicComposite;
import me.prettyprint.hector.api.beans.HColumn;
import me.prettyprint.hector.api.mutation.Mutator;
import me.prettyprint.hector.api.query.SliceQuery;

import static me.prettyprint.hector.api.factory.HFactory.createColumn;
import static me.prettyprint.hector.api.factory.HFactory.createMutator;
import static me.prettyprint.hector.api.factory.HFactory.createSliceQuery;
import static org.usergrid.persistence.cassandra.CassandraService.SHIRO_CACHES;


/**
 *
 * @author: tnine
 *
 */
public class CassandraCache implements Cache<SimplePrincipalCollection, UsergridAuthorizationInfo>
{


    private static final UUIDSerializer UUID_SER = UUIDSerializer.get();
    private static final StringSerializer STR_SER = StringSerializer.get();
    private static final DynamicCompositeSerializer DYN_SER = DynamicCompositeSerializer.get();
    private static final BytesArraySerializer BYTE_ARRAY_SER = BytesArraySerializer.get();


    private static final byte[] TRUE = { 1 };
    private static final byte[] FALSE = { 0 };

    private static final String ROLES = "roles";
    private static final String PERMISSIONS = "permissions";
    private static final String DELETED = "deleted";
    private static final String ORGS = "orgs";
    private static final String APPS = "apps";

    private static final int ONE_DAY = 60 * 60 * 24;


    private final CassandraService cassandra;

    private final String realmName;

    private int ttl = ONE_DAY;


    public CassandraCache( CassandraService cassandra, String realmName )
    {
        this.cassandra = cassandra;
        this.realmName = realmName;
    }


    @Override
    public UsergridAuthorizationInfo get( SimplePrincipalCollection key ) throws CacheException
    {
        /**
         * Write the data with ttl=0, this means we can set gc_grace = to 0 so we clean data faster when it expires
         */

        String rowKey = getRowKey( key );

        Keyspace ko = cassandra.getSystemKeyspace();

        SliceQuery<String, String, DynamicComposite> query = createSliceQuery( ko, STR_SER, STR_SER, DYN_SER );

        query.setKey( rowKey );
        query.setColumnFamily( SHIRO_CACHES );
        query.setColumnNames( ROLES, PERMISSIONS, DELETED, ORGS, APPS );

        ColumnSlice<String, DynamicComposite> results = query.execute().get();


        final HColumn<String, DynamicComposite> roleColumn = results.getColumnByName( ROLES );
        final HColumn<String, DynamicComposite> permissionsColumn = results.getColumnByName( PERMISSIONS );
        final HColumn<String, DynamicComposite> organizationsColumn = results.getColumnByName( ORGS );
        final HColumn<String, DynamicComposite> applicationsColumn = results.getColumnByName( APPS );

        final HColumn<String, DynamicComposite> deletedColumn = results.getColumnByName( DELETED );


        /**
         * We have incomplete data, return nothing
         */
        if ( roleColumn == null || permissionsColumn == null || deletedColumn == null || organizationsColumn == null
                || applicationsColumn == null )
        {
            return null;
        }

        /**
         * This entry has been marked as deleted, it just hasn't timed out yet, discard it
         */
        byte[] deleted = BYTE_ARRAY_SER.fromByteBuffer( deletedColumn.getValueBytes() );

        if ( deleted[0] == TRUE[0] )
        {
            return null;
        }

        final UsergridAuthorizationInfo authInfo = new UsergridAuthorizationInfo();

        final DynamicComposite storedRoles = roleColumn.getValue();


        for ( AbstractComposite.Component c : storedRoles.getComponents() )
        {
            final String value = ( String ) c.getValue( STR_SER );

            authInfo.addRole( value );
        }


        final DynamicComposite storedPermissions = permissionsColumn.getValue();

        for ( AbstractComposite.Component c : storedPermissions.getComponents() )
        {
            final String value = ( String ) c.getValue( STR_SER );

            authInfo.addStringPermission( value );
        }


        final DynamicComposite storedOrgs = organizationsColumn.getValue();

        List<AbstractComposite.Component<?>> components = storedOrgs.getComponents();
        int size = storedOrgs.getComponents().size();


        for ( int i = 0; i < size; i = i + 2 )
        {
            final UUID id = components.get( i ).getValue( UUID_SER );
            final String name = components.get( i + 1 ).getValue( STR_SER );

            authInfo.addOrganizationInfo( new OrganizationInfo( id, name ) );
        }


        final DynamicComposite storedApps = applicationsColumn.getValue();

        components = storedApps.getComponents();
        size = storedApps.getComponents().size();


        for ( int i = 0; i < size; i = i + 2 )
        {
            final UUID id = components.get( i ).getValue( UUID_SER );
            final String name = components.get( i + 1 ).getValue( STR_SER );

            authInfo.addApplication( new ApplicationInfo( id, name ) );
        }

        return authInfo;
    }


    @Override
    public UsergridAuthorizationInfo put( SimplePrincipalCollection key, UsergridAuthorizationInfo info )
            throws CacheException
    {
        final String rowKey = getRowKey( key );


        /**
         * Build the columns.  We use dynamic composites since we can easily serialize our strings into components
         */

        final DynamicComposite roles = new DynamicComposite();

        for ( String role : info.getRoles() )
        {
            roles.add( role );
        }

        final DynamicComposite permissions = new DynamicComposite();

        for ( String permission : info.getStringPermissions() )
        {
            permissions.add( permission );
        }


        final DynamicComposite applications = new DynamicComposite();

        for ( ApplicationInfo app : info.getApplications() )
        {
            applications.add( app.getId() );
            applications.add( app.getName() );
        }


        final DynamicComposite organizations = new DynamicComposite();

        for ( OrganizationInfo org : info.getOrganizations() )
        {
            organizations.add( org.getUuid() );
            organizations.add( org.getName() );
        }


        /**
         * Write the data
         */
        Keyspace ko = cassandra.getSystemKeyspace();

        Mutator<String> m = createMutator( ko, STR_SER );

        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( ROLES, roles, ttl, STR_SER, DYN_SER ) );

        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( PERMISSIONS, permissions, ttl, STR_SER, DYN_SER ) );

        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( ORGS, organizations, ttl, STR_SER, DYN_SER ) );

        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( APPS, applications, ttl, STR_SER, DYN_SER ) );

        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( DELETED, FALSE, ttl, STR_SER, BYTE_ARRAY_SER ) );

        m.execute();

        return info;
    }


    /** Get the cassandra row key */
    private String getRowKey( SimplePrincipalCollection key )
    {
        return String.format( "%s/%s", realmName, key.toString() );
    }


    @Override
    public UsergridAuthorizationInfo remove( SimplePrincipalCollection key ) throws CacheException
    {

        UsergridAuthorizationInfo returned = get( key );

        //nothing to do, no values
        if ( returned == null )
        {
            return null;
        }


        String rowKey = getRowKey( key );

        Keyspace ko = cassandra.getSystemKeyspace();

        Mutator<String> m = createMutator( ko, STR_SER );

        /**
         * Set set our deleted flag to true, and we expire the columns after 1 second.  This will allow us to set a
         * very low
         * gc_grace, and hence the physical data will be removed on compaction faster.  We can then set gc_grace=0
         */
        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( ROLES, new DynamicComposite(), 1, STR_SER, DYN_SER ) );

        m.addInsertion( rowKey, SHIRO_CACHES,
                createColumn( PERMISSIONS, new DynamicComposite(), 1, STR_SER, DYN_SER ) );

        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( ORGS, new DynamicComposite(), 1, STR_SER, DYN_SER ) );

        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( APPS, new DynamicComposite(), 1, STR_SER, DYN_SER ) );

        //We need to use the same TTL as the write.  Otherwise, we could potentially remove a row and lose it due to
        // compaction if a replica is down
        m.addInsertion( rowKey, SHIRO_CACHES, createColumn( DELETED, TRUE, ttl, STR_SER, BYTE_ARRAY_SER ) );

        m.execute();

        return returned;
    }


    @Override
    public void clear() throws CacheException
    {
        throw new UnsupportedOperationException( "Clear is not supported.  It requires too much iteration" );
    }


    @Override
    public int size()
    {
        throw new UnsupportedOperationException( "Size is not supported.  It requires too much iteration" );
    }


    @Override
    public Set<SimplePrincipalCollection> keys()
    {
        throw new UnsupportedOperationException( "keys is not supported.  It will most likely not load before OOM" );
    }


    @Override
    public Collection<UsergridAuthorizationInfo> values()
    {
        throw new UnsupportedOperationException( "values is not supported.  It will most likely not load before OOM" );
    }
}
