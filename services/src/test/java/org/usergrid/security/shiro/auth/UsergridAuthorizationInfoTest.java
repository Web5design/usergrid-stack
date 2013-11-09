package org.usergrid.security.shiro.auth;

import org.junit.Test;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.utils.UUIDUtils;

import java.util.UUID;

import static junit.framework.Assert.assertEquals;

/**
 *
 * @author: tnine
 *
 */
public class UsergridAuthorizationInfoTest {

  @Test
  public void verifyApplicationInfo(){

    UsergridAuthorizationInfo info = new UsergridAuthorizationInfo();

    UUID id1 = UUIDUtils.newTimeUUID();
    String name1 = "name1";

    ApplicationInfo info1 =  new ApplicationInfo(id1, name1);
    info.addApplication(info1);

    UUID id2 = UUIDUtils.newTimeUUID();
    String name2 = "name2";

    ApplicationInfo info2 = new ApplicationInfo(id2, name2);
    info.addApplication(info2);

    assertEquals(info1, info.getApplication(id1));
    assertEquals(info1, info.getApplication(name1));

    assertEquals(info2, info.getApplication(id2));
    assertEquals(info2, info.getApplication(name2));

  }

  @Test
  public void verifyOrganizationInfo(){

    UsergridAuthorizationInfo info = new UsergridAuthorizationInfo();

    UUID id1 = UUIDUtils.newTimeUUID();
    String name1 = "name1";

    OrganizationInfo info1 =  new OrganizationInfo(id1, name1);
    info.addOrganizationInfo(info1);

    UUID id2 = UUIDUtils.newTimeUUID();
    String name2 = "name2";

    OrganizationInfo info2 = new OrganizationInfo(id2, name2);
    info.addOrganizationInfo(info2);

    assertEquals(info1, info.getOrganization(id1));
    assertEquals(info1, info.getOrganization(name1));

    assertEquals(info2, info.getOrganization(id2));
    assertEquals(info2, info.getOrganization(name2));

  }
}
