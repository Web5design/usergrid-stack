/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.usergrid.batch.job;


import org.usergrid.cassandra.Concurrent;
import org.usergrid.persistence.entities.JobData;

import org.junit.Test;

import static org.junit.Assert.assertTrue;


/**
 * Class to test job runtimes
 */
@Concurrent
public class SchedulerRuntime2IT extends AbstractSchedulerRuntimeIT {
    /** Test the scheduler ramps up correctly when there are more jobs to be read after a pause */
    @Test
    public void schedulingWithNoJobs() throws InterruptedException {
        CountdownLatchJob counterJob = cassandraResource.getBean( CountdownLatchJob.class );
        // set the counter job latch size
        counterJob.setLatch( getCount() );

        for ( int i = 0; i < getCount(); i++ ) {
            scheduler.createJob( "countdownLatch", System.currentTimeMillis(), new JobData() );
        }

        // now wait until everything fires
        boolean waited = getJobListener().blockTilDone( getCount(), 15000L );

        assertTrue( "Jobs ran", waited );
        assertTrue( getCount() + " successful jobs ran", getCount() == getJobListener().getSuccessCount() );

        Thread.sleep( 5000 );

        // set the counter job latch size
        counterJob.setLatch( getCount() );

        for ( int i = 0; i < getCount(); i++ ) {
            scheduler.createJob( "countdownLatch", System.currentTimeMillis(), new JobData() );
        }

        // now wait until everything fires
        waited = getJobListener().blockTilDone( 2 * getCount(), 15000L );
        assertTrue( "Jobs ran", waited );
        assertTrue( 2 * getCount() + " successful jobs ran",
                ( 2 * getCount() ) == getJobListener().getSuccessCount() );
    }
}
