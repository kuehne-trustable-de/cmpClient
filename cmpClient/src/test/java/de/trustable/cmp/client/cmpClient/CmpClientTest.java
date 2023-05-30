package de.trustable.cmp.client.cmpClient;

/*
   Copyright 2022 Andreas Kuehne

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

 */

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for cmp client.
 */
public class CmpClientTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public CmpClientTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( CmpClientTest.class );
    }

    /**
     * Test of command args processing
     */
    public void testApp(){
    	String[] emptyArgs = {};
		int ret = CMPCmdLineClient.handleArgs(emptyArgs);
		Assert.assertEquals("arguments required", 1, ret);
		
    	String[] args = {"-h"};
		ret = CMPCmdLineClient.handleArgs(args);
		Assert.assertEquals("help is a valid option ", 0, ret);		
    }
}
