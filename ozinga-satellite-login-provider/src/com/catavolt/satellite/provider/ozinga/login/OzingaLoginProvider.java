package com.catavolt.satellite.provider.ozinga.login;

import java.io.FileInputStream;
import java.io.StringReader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.ws.Response;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import com.sun.javafx.binding.StringFormatter;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.xml.xpath.XPathExpression;
import org.xml.sax.InputSource;

import com.catavolt.satellite.spi.AbstractSPCustomProviderHandler;
import com.catavolt.satellite.spi.SPException;
import com.catavolt.satellite.spi.SatelliteContext;
import sun.plugin2.message.Message;

public class OzingaLoginProvider extends AbstractSPCustomProviderHandler {

//****************************************************************************
    // FIELDS
    //****************************************************************************

    // We convert all keys to lowercase when extracting options
    public static final String CONFIG_FILE_KEY = "configfile";
    // public static final String FAILED_ATTEMPTS_KEY = "failedattempts";
    public static final String LOG_KEY = "log";
    public static final String ASSIGNED_USER_KEY = "assigneduser";
    public static final String SELF_SIGNED_CERT_KEY = "selfsignedcert";
    public static final String DOMAIN_KEY = "domain";
    public static final String LDAP_KEY = "ldap";
    public static final String LDAPS_KEY = "ldaps";
    public static final String SEARCH_NAME = "searchname";


    public static final String DB_KEY_INTERNAL = "internal-db";
    public static final String DB_PROFILE_KEY_INTERNAL = "internal-dbprofile";

    /*
    public static final String DB_KEY_MYOZ = "myozinga-db";
    public static final String DB_PROFILE_KEY_MYOZ = "myozinga-dbprofile";
    */

    public static final String DB_COUNT_KEY = "db-count";
    public static final String DB_URL_KEY_BASE = "db-";
    public static final String DB_PROFILE_KEY_BASE = "dbprofile-";


    // public static final int LOG_NONE = 0;

    public static final int LOG_ERROR = 10;
    public static final int LOG_INFO = 20;
    public static final int LOG_DEBUG = 30;


    private static class DBLoginResponse {
        public Boolean LoginValid = false;
        public StringBuffer SPResponse = new StringBuffer();
        public Boolean BreakDBLoop = false;

        public String toString() {
            return "DB Login Response {valid: " + LoginValid + " Response: " + SPResponse.toString() + "}";
        }
    }

//****************************************************************************
    // CONSTRUCTOR
    //****************************************************************************

    //****************************************************************************
    // INSTANCE METHODS
    //****************************************************************************

    /**
     * String return value is XML in the format of:
     * <Response>
     *   <AssignedUser name='Catavolt_Admin_User' />
     *   <UserProperties>
     *     <UserProperty name='AAA'><Value><![CDATA[HOTEP]]></Value></UserProperty>
     *   </UserProperties>
     * </Response>
     *
     * null can be returned for no overrides.  AssignedUser and UserProperties are optional tags
     */

    public String authenticate(SatelliteContext pSC, String pSystemName, String pOptions,String pUser, String pPassword, List<String> pChallengeAnswers) throws SPException {

        /*
        if ("myozinga".equals(pUser) && "07myOZ2016$".equals(pPassword)) {
            return null;
        }
        */

        StringBuffer wReturnBuffer = new StringBuffer(4000);
        Map<String,String> wOptionsMap = parseOptions(pOptions);

        Properties wProps = new Properties();
        try {
            wProps.load(new FileInputStream(wOptionsMap.get(CONFIG_FILE_KEY)));
        } catch (Exception wEx) {
            System.out.println("OzingaLoginProvider: Error loading properties file.");
            wEx.printStackTrace();
            throw new SPException(wEx);
        }

        String wLogLevel = wProps.getProperty(LOG_KEY);
        writeLogMessage(MessageFormat.format("Authenticating user: {0}", pUser), LOG_INFO, wLogLevel);

        writeLogMessage("******************** Options ********************", LOG_DEBUG, wLogLevel);
        for (Map.Entry<String, String> wNext : wOptionsMap.entrySet()) {
            writeLogMessage(wNext.getKey() + ":" + wNext.getValue(), LOG_DEBUG, wLogLevel);
        }
        writeLogMessage("*************************************************", LOG_DEBUG, wLogLevel);

        String wAllowSelfSignedOption = wProps.getProperty(SELF_SIGNED_CERT_KEY);
        boolean wAllowSelfSignedCert = "true".equals(wAllowSelfSignedOption);

        if (wAllowSelfSignedCert){
            trustSelfSignedSSL();
        }

        boolean wADPassed = true;

        /*
         * Check the login against the DC first
         * Can use either DN, NTLM or UPN style credentials
         */

        String wLdapURL = wProps.getProperty(LDAP_KEY);
        String wLdapsURL = wProps.getProperty(LDAPS_KEY);
        String wDomain = wProps.getProperty(DOMAIN_KEY);
        String wSearchName = wProps.getProperty(SEARCH_NAME);

        StringBuilder wUserRoles= new StringBuilder();
        StringBuilder wUserProps = new StringBuilder();

        if (wLdapsURL == null) {
            if ((wLdapURL == null) || !wLdapURL.startsWith("ldap:")) {
                throw new SPException(getFormatErrorString(), null);
            }
        } else {
            if (!wLdapsURL.startsWith("ldaps:")) {
                throw new SPException(getFormatErrorString(), null);
            }
        }

        if (wSearchName == null) {
            throw new SPException("Properties file missing searchname setting.", null);
        }

        if (wDomain == null) {
            throw new SPException("Properties file missing domain setting.", null);
        }

        if ((pPassword == null) || pPassword.trim().isEmpty()) {
            System.out.println("Authentication Error - User: " + pUser + " Error: Blank password specified.");
            throw new SPException("User Id or Password is invalid");
        }

        Hashtable<String,String> wEnv = new Hashtable<String,String>();
        wEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        wEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
        wEnv.put(Context.SECURITY_PRINCIPAL, MessageFormat.format("{0}@{1}", pUser, wDomain));
        wEnv.put(Context.SECURITY_CREDENTIALS, pPassword);

        if (wLdapsURL != null) {
            wEnv.put(Context.SECURITY_PROTOCOL, "ssl");
            wEnv.put(Context.PROVIDER_URL, wLdapsURL);
        } else {
            wEnv.put(Context.PROVIDER_URL, wLdapURL);
        }
        try {
            //Create the initial directory context
            LdapContext wContext = new InitialLdapContext(wEnv, null);
            //initialize counter to total the results
            SearchControls wSearchCtls = new SearchControls();
            wSearchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            wSearchCtls.setCountLimit(1);
            wSearchCtls.setReturningAttributes(new String[]{"memberOf"});
            String wSearchFilter = MessageFormat.format("(sAMAccountName={0})", pUser);
            NamingEnumeration wEnumeration = wContext.search(wSearchName, wSearchFilter, wSearchCtls);
            while (wEnumeration.hasMoreElements()) {
                SearchResult wSR = (SearchResult) wEnumeration.next();
                Attributes wAttrs = wSR.getAttributes();
                if (wAttrs != null) {
                    Attribute wAttr = wAttrs.get("memberOf");
                    NamingEnumeration wAllGroups = wAttr.getAll();
                    while (wAllGroups.hasMoreElements()) {
                        String wNextGroup = (String) wAllGroups.nextElement();
                        writeLogMessage("  NextGroup: " + wNextGroup, LOG_DEBUG, wLogLevel);
                        if (wNextGroup.startsWith("CN=")) {
                            int wIndex = wNextGroup.indexOf(',');
                            if (wIndex > -1) {
                                String wMemberOf = wNextGroup.substring(3, wIndex);
                                writeLogMessage("   Member Of: " + wMemberOf, LOG_DEBUG, wLogLevel);
                                //load the roles into the user.
                                wUserRoles.append("<SecurityRole><![CDATA[").append(wMemberOf).append("]]></SecurityRole>");
                            }
                        }
                    }
                }
            }

            wContext.close();

        } catch (NamingException wExc) {
            wADPassed = false;
            //writeLogMessage("LDAP Authentication Error - User: " + pUser + " Naming Error: " + wExc.getMessage(), LOG_ERROR, wLogLevel);
        } catch (Exception wExc) {
            wADPassed = false;
            writeLogMessage("LDAP Authentication Error - User: " + pUser + " Error: " + wExc.getMessage(), LOG_ERROR, wLogLevel);
        }

        writeLogMessage("Ldap authentication check returned: " + String.valueOf(wADPassed), LOG_DEBUG, wLogLevel);

    /* If AD confirms then load the properties from the internal user sql tables */
        if (wADPassed) {
            writeLogMessage("Ldap login successful for: " + pUser, LOG_INFO, wLogLevel);

            String wDBURL = wProps.getProperty(DB_KEY_INTERNAL);
            String wDBProfile = wProps.getProperty(DB_PROFILE_KEY_INTERNAL);
            String wAssignedUser = (wProps.getProperty(ASSIGNED_USER_KEY) != null) ? wProps.getProperty(ASSIGNED_USER_KEY) : pUser ;

            if ((wDBURL != null) && (wDBProfile != null)) {

                String wUnencodedProfile = HexStringConverter.getInstance().toString(wDBProfile);
                int wIndex = wUnencodedProfile.indexOf(":::");
                if (wIndex == -1) {
                    throw new SPException("DB Profile Token format is invalid.");
                }
                String wDBUser = wUnencodedProfile.substring(0, wIndex);
                String wDBPassword = wUnencodedProfile.substring(wIndex+3);

                Connection wConn = null;
                PreparedStatement wPS = null;
                ResultSet wRS = null;
                try {
                    writeLogMessage("Connecting to user props DB, URL: " + wDBURL + ", User: " + wDBUser, LOG_DEBUG, wLogLevel);

                    wConn = DriverManager.getConnection(wDBURL, wDBUser, wDBPassword);
                    // Use PreparedStatement to avoid SQL Injection Attack
                    String wSQL = "SELECT MEMBERS.ROLE FROM CV_AD_USER ADUSER" +
                            " INNER JOIN CV_USER_ROLE_MEMBERS MEMBERS " +
                            " ON MEMBERS.USERNAME = ADUSER.USERNAME " +
                            "WHERE ADUSER.USERNAME = ? AND ADUSER.USER_STATUS = 'A' ";
                    wPS = wConn.prepareStatement(wSQL);
                    wPS.setString(1, pUser.toLowerCase());
                    wRS = wPS.executeQuery();
                    if (wRS.next()) {
                        writeLogMessage("Found Match for User: " + pUser , LOG_DEBUG, wLogLevel);

                        //load the roles into the user.
                        wUserRoles.append("<SecurityRole><![CDATA[").append(wRS.getString(1)).append("]]></SecurityRole>");
                        while (wRS.next()) {
                            wUserRoles.append("<SecurityRole><![CDATA[").append(wRS.getString(1)).append("]]></SecurityRole>");
                        }

                    } else {
                        System.out.println("Authentication Error - User: " + pUser + " Error: User not found.");
                        throw new SPException("User Id or Password is invalid");
                    }

                    //now set the user properties assigned to the user.
                    wSQL = "SELECT property_name, property_value FROM CV_USER_PROPERTY " +
                            "WHERE lower(user_id) = ? ";
                    wPS = wConn.prepareStatement(wSQL);
                    wPS.setString(1, pUser.toLowerCase());
                    wRS = wPS.executeQuery();
                    while (wRS.next()) {
                        wUserProps.append("<UserProperty name='"+ wRS.getString(1) +"'><Value><![CDATA[" + wRS.getString(2) +"]]></Value></UserProperty>");
                        if (
                                (ASSIGNED_USER_KEY.equalsIgnoreCase(wRS.getString(1)))) {
                            wAssignedUser = wRS.getString(2);
                        }
                    }
                    if (wRS != null) {
                        wRS.close();
                    }
                    if (wPS != null) {
                        wPS.close();
                    }
                    if (wConn != null) {
                        wConn.close();
                    }
                } catch (SPException wExc) {
                    throw wExc;
                } catch (Throwable wExc) {
                    System.out.println("Error checking db table: " + wExc.getMessage());
                    throw new SPException("Error logging in. Unable to locate user in seurity table.");
                }
            }

            wReturnBuffer.append("<Response>").append("<AssignedUser name='").append(wAssignedUser).append( "' />");

            //if the assigned user is not set in the options
            //let Catavolt associate it with a catavolt account
            if (!pUser.equals(wAssignedUser )) {

                wReturnBuffer.append("<UserProperties>")
                        .append("<UserProperty name='CURRENT_EXTERNAL_USER_ID'><Value><![CDATA[").append(pUser.toLowerCase()).append("]]></Value></UserProperty>")
                        .append(wUserProps.toString())
                        .append("</UserProperties>");
                wReturnBuffer.append("<SecurityRoles>")
                        .append(wUserRoles.toString())
                        .append("</SecurityRoles>");
            }
            wReturnBuffer.append("</Response>");


        } else {
            writeLogMessage("Ldap login failed...", LOG_DEBUG, wLogLevel);

            int wDBNumber;
            try {
                    wDBNumber = Integer.valueOf(wProps.getProperty(DB_COUNT_KEY));
            } catch (Exception wErr) {
                throw new SPException(MessageFormat.format("Error logging in. Invalid setting for DB Count Key: {0}", wProps.getProperty(DB_COUNT_KEY)));
            }

            for (int i=1; i< wDBNumber; i++) {

                DBLoginResponse wLoginResponse = loginWithDB(i, pUser, pPassword, wReturnBuffer, wProps, wLogLevel);

                        /* ####################################################################
                         * Edit the lines below to respond to a different return message from
                         * the login SP.
                         *  #################################################################*/
                if (wLoginResponse.BreakDBLoop) {
                    wReturnBuffer = wLoginResponse.SPResponse;
                    break;
                }
            }

        }

    /*Check for errors from the SP */
        boolean wThrowCustomError = false;
        StringBuilder wErrorString = new StringBuilder();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document wSPDoc = builder.parse(new InputSource(new StringReader(wReturnBuffer.toString())));

            XPathFactory wXPathfactory = XPathFactory.newInstance();
            XPath wXpath = wXPathfactory.newXPath();
            XPathExpression wExpr = wXpath.compile("/Response/Message[@type='error']/Text");
            NodeList wNodeList = (NodeList) wExpr.evaluate(wSPDoc, XPathConstants.NODESET);

            if (wNodeList.getLength() > 0) {
                for (int i=0; i< wNodeList.getLength(); i++) {
                    Node wErrorNode = wNodeList.item(i);
                    wErrorString.append(wErrorNode.getTextContent());
                }
                wThrowCustomError = true;
            }

    /* Return the response */
        } catch (Exception wExc) {
            writeLogMessage("Error processing return message XML: "+ wExc.getMessage(), LOG_ERROR, wLogLevel);
        }

        if (wThrowCustomError){
            writeLogMessage("Returning error message: "+ wErrorString.toString(), LOG_DEBUG, wLogLevel);
            throw new SPException(wErrorString.toString());
        }

        writeLogMessage("Returning response for " + pUser + ": ", LOG_DEBUG, wLogLevel);
        writeLogMessage(wReturnBuffer.toString(), LOG_DEBUG, wLogLevel);

        return wReturnBuffer.toString();
    }

    private DBLoginResponse loginWithDB(int pDBNumber, String pUser, String pPassword,StringBuffer wReturnBuffer, Properties wProps, String wLogLevel) {

        DBLoginResponse wRepsonse = new DBLoginResponse();

  /* ############## MyOzinga Login Process #################### */
  /* If AD fails, check the login against the MyOzinga sql tables */
        writeLogMessage("Checking DB tables for: " + pUser, LOG_DEBUG, wLogLevel);
        String wDBNumber = Integer.toString(pDBNumber);

  /* here we'll call an SP that Ozinga maintains. It accepts the parameters and handles
  building the entire Response */
        String wDBURL = wProps.getProperty(DB_URL_KEY_BASE + wDBNumber);
        String wDBProfile = wProps.getProperty(DB_PROFILE_KEY_BASE + wDBNumber);

        if ((wDBURL != null) && (wDBProfile != null)) {

            String wUnencodedProfile = HexStringConverter.getInstance().toString(wDBProfile);
            int wIndex = wUnencodedProfile.indexOf(":::");
            if (wIndex == -1) {
                throw new SPException("DB Profile Token format is invalid.");
            }
            String wDBUser = wUnencodedProfile.substring(0, wIndex);
            String wDBPassword = wUnencodedProfile.substring(wIndex + 3);

            Connection wConn = null;
            CallableStatement wCS = null;
            try {
                writeLogMessage("Connecting to DB, URL: " + wDBURL + ", User: " + wDBUser,
                        LOG_DEBUG, wLogLevel);

                wConn = DriverManager.getConnection(wDBURL, wDBUser, wDBPassword);
                // Use PreparedStatement to avoid SQL Injection Attack
                String wSQL = "{call spSysAuthenticate(?, ?, ?, ?)}";
                wCS = wConn.prepareCall(wSQL);
                wCS.setString(1, pUser);
                wCS.setString(2, pPassword);
                wCS.registerOutParameter(3, Types.VARCHAR);
                wCS.registerOutParameter(4, Types.VARCHAR);
                wCS.execute();

      /*
       * override any previous return comments and let the SP handle it This
       * is by design as the message coming back from a failure can cover
       * both login failure cases
       */
                wReturnBuffer = new StringBuffer(wCS.getString(3));

      /*
       * Parse the return message and set the appropriate response
       */
//      wRepsonse.LoginValid = true;
                wRepsonse.SPResponse = wReturnBuffer;
                wRepsonse.BreakDBLoop = wCS.getString(4).equals("T");

                if (wCS != null) {
                    wCS.close();
                }
                if (wConn != null) {
                    wConn.close();
                }
            } catch (SPException wExc) {
                throw wExc;
            } catch (Throwable wExc) {
                writeLogMessage("Error logging in: " + wExc.getMessage(), LOG_ERROR, wLogLevel);
                throw new SPException(MessageFormat.format("Error logging in. ::: {0} ::: {1}", wRepsonse.SPResponse, wRepsonse.BreakDBLoop));
            }
        }
        return wRepsonse;
    }

    private final String getFormatErrorString() {
        return "Provider Options must be in format (LDAPS=ldaps://xxx.xx.xx.xxx:xxx)(LDAP=ldap://xx.xx.xx.xx:xxx)(DOMAIN=cccc)(LOG=true)";
    }

    private final Map<String,String> parseOptions(String pOptions)
        throws SPException
    {
        if ((pOptions == null) || pOptions.trim().isEmpty()) {
            throw new SPException(getFormatErrorString(), null);
        }

        Map<String, String> wAnswer = new HashMap<String, String>();
        int wOpenParenIndex = pOptions.indexOf('(');
        int wCloseParenIndex = pOptions.indexOf(')');
        while (wOpenParenIndex > -1) {
            if (wCloseParenIndex == -1) {
                throw new SPException(getFormatErrorString(), null);  // Mismatched parentheses
            }
            String wOptionString = pOptions.substring(wOpenParenIndex + 1, wCloseParenIndex);
            int wEqualIndex = wOptionString.indexOf('=');
            if ((wEqualIndex == -1) || (wEqualIndex == wOptionString.length() - 1)) {
                throw new SPException(getFormatErrorString(), null);  // Missing =
            }
            String wNextKey = wOptionString.substring(0, wEqualIndex);
            String wNextValue = wOptionString.substring(wEqualIndex + 1);
            wAnswer.put(wNextKey.trim().toLowerCase(), wNextValue.trim());

            // Get to next option
            wOpenParenIndex = pOptions.indexOf('(', wCloseParenIndex);
            if (wOpenParenIndex > -1) {
                wCloseParenIndex = pOptions.indexOf(')', wOpenParenIndex);
            }
        }
        return wAnswer;
    }

    public static void trustSelfSignedSSL() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            X509TrustManager tm = new X509TrustManager() {

                public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                }

                public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };
            ctx.init(null, new TrustManager[]{tm}, null);
            SSLContext.setDefault(ctx);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void writeLogMessage(String pMessage, int pMessageLevel, String pLogLevel) {

        int wLogSetting = 10;

        try {
            wLogSetting = Integer.parseInt(pLogLevel);
        } catch (Exception wExc) {

        }

        if (wLogSetting >= pMessageLevel) {
            System.out.println(pMessage);
        }
    }
}
