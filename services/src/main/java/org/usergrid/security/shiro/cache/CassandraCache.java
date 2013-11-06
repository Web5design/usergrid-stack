package org.usergrid.security.shiro.cache;

import me.prettyprint.cassandra.serializers.DynamicCompositeSerializer;
import me.prettyprint.cassandra.serializers.StringSerializer;
import me.prettyprint.hector.api.Keyspace;
import me.prettyprint.hector.api.beans.AbstractComposite;
import me.prettyprint.hector.api.beans.ColumnSlice;
import me.prettyprint.hector.api.beans.DynamicComposite;
import me.prettyprint.hector.api.beans.HColumn;
import me.prettyprint.hector.api.mutation.Mutator;
import me.prettyprint.hector.api.query.ColumnQuery;
import me.prettyprint.hector.api.query.QueryResult;
import me.prettyprint.hector.api.query.SliceQuery;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.management.UserInfo;
import org.usergrid.persistence.cassandra.CassandraService;
import org.usergrid.security.AuthPrincipalInfo;
import org.usergrid.security.shiro.principals.*;
import org.usergrid.utils.JsonUtils;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;

import static me.prettyprint.hector.api.factory.HFactory.createColumn;
import static me.prettyprint.hector.api.factory.HFactory.*;
import static org.usergrid.persistence.cassandra.CassandraService.*;
import static org.usergrid.persistence.cassandra.CassandraService.PRINCIPAL_TOKEN_CF;
import static org.usergrid.persistence.cassandra.CassandraService.TOKENS_CF;
import static org.usergrid.utils.ConversionUtils.HOLDER;
import static org.usergrid.utils.ConversionUtils.bytebuffer;

/**
 *
 * @author: tnine
 *
 */
public class CassandraCache implements Cache<SimplePrincipalCollection, SimpleAuthorizationInfo>, CacheInvalidation {


  private static final StringSerializer STR_SER = StringSerializer.get();
  private static final DynamicCompositeSerializer DYN_SER = DynamicCompositeSerializer.get();

  private static final String ROLES = "roles";
  private static final String PERMISSIONS = "permissions";

  private static final int ONE_DAY = 60*60*24;


  private final CassandraService cassandra;

  private final String realmName;

  private int ttl= ONE_DAY;

  public CassandraCache(CassandraService cassandra, String realmName){
    this.cassandra = cassandra;
    this.realmName = realmName;
  }


  @Override
  public SimpleAuthorizationInfo get(SimplePrincipalCollection key) throws CacheException {
    /**
     * Write the data with ttl=0, this means we can set gc_grace = to 0 so we clean data faster when it expires
     */

    String rowKey = getRowKey(key);

    Keyspace ko = cassandra.getSystemKeyspace();

    SliceQuery<String, String, DynamicComposite> query = createSliceQuery(ko, STR_SER, STR_SER, DYN_SER);

    query.setKey(rowKey);
    query.setColumnFamily(SHIRO_CACHES);
    query.setColumnNames(ROLES, PERMISSIONS);

    ColumnSlice<String, DynamicComposite> results = query.execute().get();


    final HColumn<String, DynamicComposite> roleColumn =  results.getColumnByName(ROLES);
    final HColumn<String, DynamicComposite> permissionsColumn = results.getColumnByName(PERMISSIONS);

    /**
     * We have incomplete data, return nothing
     */
    if(roleColumn == null || permissionsColumn == null){
      return null;
    }

    final SimpleAuthorizationInfo authInfo = new SimpleAuthorizationInfo();

    final DynamicComposite storedRoles = roleColumn.getValue();


    for(AbstractComposite.Component c: storedRoles.getComponents()){
      authInfo.addRole((String) c.getValue(STR_SER));
    }


    final DynamicComposite storedPermissions = permissionsColumn.getValue();

    for(AbstractComposite.Component c: storedPermissions.getComponents()){
      authInfo.addStringPermission((String) c.getValue(STR_SER));
    }

    return authInfo;

  }

  @Override
  public SimpleAuthorizationInfo put(SimplePrincipalCollection key, SimpleAuthorizationInfo info) throws CacheException {
    final String rowKey = getRowKey(key);


    /**
     * Build the columns.  We use dynamic composites since we can easily serialize our strings into components
     */

    final DynamicComposite roles = new DynamicComposite();

    for(String role: info.getRoles()){
      roles.add(role);
    }

    final DynamicComposite permissions = new DynamicComposite();

    for(String permission: info.getStringPermissions()){
      permissions.add(permission);
    }


    /**
     * Write the data
     */
    Keyspace ko = cassandra.getSystemKeyspace();

    Mutator<String> m = createMutator(ko, STR_SER);

    m.addInsertion(rowKey, SHIRO_CACHES, createColumn(ROLES, roles, ttl, STR_SER, DYN_SER ));

    m.addInsertion(rowKey, SHIRO_CACHES, createColumn(PERMISSIONS, permissions, ttl, STR_SER, DYN_SER ));

    m.execute();

    return info;
  }

  /**
   * Get the cassandra row key
   * @param key
   * @return
   */
  private String getRowKey(SimplePrincipalCollection key){
    return key.toString();
  }


  @Override
  public SimpleAuthorizationInfo remove(SimplePrincipalCollection key) throws CacheException {

    SimpleAuthorizationInfo returned = get(key);

    //nothing to do, no values
    if(returned == null){
      return null;
    }

    /**
     * Write the data with ttl=0, this means we can set gc_grace = to 0 so we clean data faster when it expires
     */

    String rowKey = getRowKey(key);

    Keyspace ko = cassandra.getSystemKeyspace();

    Mutator<String> m = createMutator(ko, STR_SER);

    m.addInsertion(rowKey, SHIRO_CACHES, createColumn(ROLES, new DynamicComposite(), 0, STR_SER, DYN_SER ));

    m.addInsertion(rowKey, SHIRO_CACHES, createColumn(PERMISSIONS, new DynamicComposite(), 0, STR_SER, DYN_SER ));

    m.execute();

    return returned;
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

  @Override
  public void invalidateOrg(OrganizationInfo organization) {
    final OrganizationPrincipal principal = new OrganizationPrincipal(organization);


    remove(getShiroPrincipal(principal));

  }

  @Override
  public void invalidateGuest(ApplicationInfo application) {
    final ApplicationGuestPrincipal principal = new ApplicationGuestPrincipal(application);


    remove(getShiroPrincipal(principal));
  }

  @Override
  public void invalidateUser(UUID application, UserInfo user) {
    final ApplicationUserPrincipal principal = new ApplicationUserPrincipal(application, user);

    remove(getShiroPrincipal(principal));
  }

  @Override
  public void invalidateApplication(ApplicationInfo applicationInfo) {
    final ApplicationPrincipal principal = new ApplicationPrincipal(applicationInfo);

    remove(getShiroPrincipal(principal));
  }

  private SimplePrincipalCollection getShiroPrincipal(PrincipalIdentifier id){
    return new SimplePrincipalCollection(id, realmName);
  }
}
