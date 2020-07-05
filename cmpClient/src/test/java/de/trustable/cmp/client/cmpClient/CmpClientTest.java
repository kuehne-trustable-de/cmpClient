package de.trustable.cmp.client.cmpClient;

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
		int ret = CMPClient.handleArgs(emptyArgs);
		Assert.assertEquals("arguments required", 1, ret);
		
    	String[] args = {"-h"};
		ret = CMPClient.handleArgs(args);
		Assert.assertEquals("help is a valid option ", 0, ret);		
    }
}
