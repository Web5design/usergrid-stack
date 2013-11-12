package org.usergrid;


import org.junit.ClassRule;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.usergrid.cassandra.CassandraResource;
import org.usergrid.cassandra.Concurrent;
import org.usergrid.cassandra.ConcurrentSuite;
import org.usergrid.persistence.AllInCollectionIT;
import org.usergrid.persistence.AllInConnectionIT;
import org.usergrid.persistence.AllInConnectionNoTypeIT;
import org.usergrid.persistence.MultiOrderByCollectionIT;
import org.usergrid.persistence.MultiOrderByComplexUnionCollectionIT;
import org.usergrid.persistence.MultiOrderByComplexUnionConnectionIT;
import org.usergrid.persistence.SingleOrderByBoundRangeScanAscCollectionIT;
import org.usergrid.persistence.SingleOrderByBoundRangeScanAscConnectionIT;
import org.usergrid.persistence.SingleOrderByBoundRangeScanDescCollectionIT;
import org.usergrid.persistence.SingleOrderByBoundRangeScanDescConnectionIT;
import org.usergrid.persistence.SingleOrderByComplexIntersectionCollectionIT;
import org.usergrid.persistence.SingleOrderByComplexIntersectionConnectionIT;
import org.usergrid.persistence.SingleOrderByComplexUnionCollectionIT;
import org.usergrid.persistence.SingleOrderByComplexUnionConnectionIT;
import org.usergrid.persistence.SingleOrderByLessThanLimitCollectionIT;
import org.usergrid.persistence.SingleOrderByLessThanLimitConnectionIT;
import org.usergrid.persistence.SingleOrderByMaxLimitCollectionIT;
import org.usergrid.persistence.SingleOrderByMaxLimitConnectionIT;
import org.usergrid.persistence.SingleOrderByNoIntersectionCollectionIT;
import org.usergrid.persistence.SingleOrderByNoIntersectionConnectionIT;
import org.usergrid.persistence.SingleOrderByNotCollectionIT;
import org.usergrid.persistence.SingleOrderByNotConnectionIT;
import org.usergrid.persistence.SingleOrderBySameRangeScanGreaterCollectionIT;
import org.usergrid.persistence.SingleOrderBySameRangeScanGreaterConnectionIT;
import org.usergrid.persistence.SingleOrderBySameRangeScanGreaterThanEqualCollectionIT;
import org.usergrid.persistence.SingleOrderBySameRangeScanLessCollectionIT;
import org.usergrid.persistence.SingleOrderBySameRangeScanLessConnectionIT;
import org.usergrid.persistence.SingleOrderBySameRangeScanLessThanEqualCollectionIT;
import org.usergrid.persistence.SingleOrderBySameRangeScanLessThanEqualConnectionIT;


@RunWith( ConcurrentSuite.class )
@Suite.SuiteClasses(
    {
        AllInCollectionIT.class,
        AllInConnectionIT.class,
        AllInConnectionNoTypeIT.class,
        MultiOrderByCollectionIT.class,
        MultiOrderByComplexUnionCollectionIT.class,
        MultiOrderByComplexUnionConnectionIT.class,
        SingleOrderByBoundRangeScanAscCollectionIT.class,
        SingleOrderByBoundRangeScanAscConnectionIT.class,
        SingleOrderByBoundRangeScanDescCollectionIT.class,
        SingleOrderByBoundRangeScanDescConnectionIT.class,
        SingleOrderByComplexIntersectionCollectionIT.class,
        SingleOrderByComplexIntersectionConnectionIT.class,
        SingleOrderByComplexUnionCollectionIT.class,
        SingleOrderByComplexUnionConnectionIT.class,
        SingleOrderByLessThanLimitCollectionIT.class,
        SingleOrderByLessThanLimitConnectionIT.class,
        SingleOrderByMaxLimitCollectionIT.class,
        SingleOrderByMaxLimitConnectionIT.class,
        SingleOrderByNoIntersectionCollectionIT.class,
        SingleOrderByNoIntersectionConnectionIT.class,
        SingleOrderByNotCollectionIT.class,
        SingleOrderByNotConnectionIT.class,
        SingleOrderBySameRangeScanGreaterCollectionIT.class,
        SingleOrderBySameRangeScanGreaterConnectionIT.class,
        SingleOrderBySameRangeScanGreaterThanEqualCollectionIT.class,
        SingleOrderBySameRangeScanLessCollectionIT.class,
        SingleOrderBySameRangeScanLessConnectionIT.class,
        SingleOrderBySameRangeScanLessThanEqualCollectionIT.class,
        SingleOrderBySameRangeScanLessThanEqualConnectionIT.class
    } )
@Concurrent ( threads = 15 )
public class ConcurrentCoreIteratorITSuite
{
    @ClassRule
    public static CassandraResource cassandraResource = CassandraResource.newWithAvailablePorts( "coreManager" );
}
