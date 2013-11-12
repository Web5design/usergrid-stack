package org.usergrid.security.shiro;

import org.apache.shiro.subject.PrincipalCollection;
import org.usergrid.management.ManagementService;
import org.usergrid.persistence.EntityManagerFactory;
import org.usergrid.security.shiro.auth.UsergridAuthorizationInfo;
import org.usergrid.security.tokens.TokenService;

/**
 *
 * @author: tnine
 *
 */
public interface UsergridRealm {


  /**
   * Get the entity manager factory
   * @return
   */
  public EntityManagerFactory getEmf();

  /**
   * Get the management service
   * @return
   */
  public ManagementService getManagement();

  /**
   * Get the token service
   * @return
   */
  public TokenService getTokens();

  /**
   * Return true if the super user is enabled for this realm
   * @return
   */
  public boolean isSuperUserEnabled();

  /**
   * Get the super user username
   * @return
   */
  public String getSuperUser();

  /**
   * Get the Usergrid authorization info for this principal collection. Will check the cache first
   * before re-creating
   * @param collection
   * @return
   */
  public UsergridAuthorizationInfo getAuthorizationInfo(PrincipalCollection collection);
}
