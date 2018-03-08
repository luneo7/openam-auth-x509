/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2005 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * Portions Copyrighted 2013-2015 ForgeRock AS.
 *
 * Portions Copyrighted 2016 Lucas Rogerio Caetano Ferreira
 */

package com.sun.identity.authentication.modules.x509;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;

import com.iplanet.am.util.JSSInit;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.security.x509.CertUtils;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.X509CertificateCallback;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.security.cert.AMCRLStore;
import com.sun.identity.security.cert.AMCertPath;
import com.sun.identity.security.cert.AMCertStore;
import com.sun.identity.security.cert.AMLDAPCertStoreParameters;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.encode.Base64;

import org.forgerock.openam.ldap.LDAPUtils;
import org.forgerock.opendj.ldap.DN;
import org.forgerock.opendj.ldap.LDAPUrl;
import org.mozilla.jss.CryptoManager;

import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.GeneralNames;
import sun.security.x509.OtherName;
import sun.security.x509.RFC822Name;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class X509 extends AMLoginModule {

    private static java.util.Locale locale = null;
    private ResourceBundle bundle = null;

    private String userTokenId = null;
    private X509Certificate thecert = null;

    // from profile server.
    // default: MUST HAVE where is the ldap server.
    private String amAuthX509_serverHost;
    // default: values stored in auth.certificate.ldap.server.context;
    // think ok to be nil.
    private String amAuthX509_startSearchLoc;
    // none, simple or CRAM-MD5 (default to NONE)
    private String amAuthX509_securityType;
    // ldap user name [if missing default to amAuthX509_securityType to none.]
    private String amAuthX509_principleUser;
    // ldap user's passwd
    // [if missing default to amAuthX509_securityType to none.]
    private String amAuthX509_principlePasswd;
    // use ssl to talk to ldap. default is false.
    private String amAuthX509_useSSL;
    // Field in Cert to user to access user profile.  default to DN
    private String amAuthX509_userProfileMapper;
    // Alternate Field in Cert to userid to access user profile
    // if above is "other"
    private String amAuthX509_altUserProfileMapper;
    // SubjectAltNameExtension Value Type OID
    // This OID type of value is retrieved and used to access user profile
    private String amAuthX509_subjectAltExtMapper;
    // check user cert against revoke list in LDAP.
    private String amAuthX509_chkCRL;
    // check CA cert against revoke list in LDAP.
    private String amAuthX509_validateCA;
    // attr to use in search for user cert in CRL in LDAP
    private String amAuthX509_chkAttrCRL = null;
    // attributes to use in searchfilter to find crlDistributionPoint entry in LDAP
    // content of searchfilter is described in AMCRLStore to avoid duplication
    private String[] amAuthX509_chkAttributesCRL = null;
    // params to use in accessing CRL DP
    private String amAuthX509_uriParamsCRL = null;
    // check user cert with cert in LDAP.
    private String amAuthX509_chkCertInLDAP;
    // attr to use in search for user cert in LDAP
    private String amAuthX509_chkAttrCertInLDAP = null;
    // this is what appears in the user selectable choice field.
    private String amAuthX509_emailAddrTag;
    private int amAuthX509_serverPort =389;
    private boolean portal_gw_cert_auth_enabled = false;
    private Set portalGateways = null;
    // HTTP Header name to have clien certificate in servlet request.
    private String certParamName = null;
    private boolean ocspEnabled = false;
    private boolean crlEnabled = false;
    private AMLDAPCertStoreParameters ldapParam = null;

    // configurations
    private Map options;
    private X509AuthPrincipal userPrincipal;
    private CallbackHandler callbackHandler;
    static final int ldap_version = 3;

    private static final String amAuthX509 = "amAuthX509";

    private static com.sun.identity.shared.debug.Debug debug = null;

    static String UPNOID = "1.3.6.1.4.1.311.20.2.3";

    /**
	 * OID para dados de pessoa fisica nas primeiras 8 (oito) posicoes, a data de nascimento do titular, no formato
	 * ddmmaaaa; nas 11 (onze) posições subsequentes, o Cadastro de Pessoa Fisica (CPF) do titular; nas 11 (onze)
	 * posicoes subsequentes, o Numero de Identificacao Social - NIS (PIS,PASEP ou CI); nas 15 (quinze) posicoes
	 * subsequentes, o numero do Registro Geral (RG) do titular; nas 6 (seis) posicoes subsequentes, as siglas do orgao
	 * expedidor do RG e respectiva unidade da federacao
	 */
    static String CPFOID = "2.16.76.1.3.1";

	/**
	 * OID para Cadastro Nacional de Pessoa Juridica (CNPJ) da pessoa juridica titular do certificado
	 */
    static String CNPJOID = "2.16.76.1.3.3";

    static boolean usingJSSHandler = false;

    private String amAuthX509_cacheCRL;
    private boolean doCRLCaching = true;

    //attribute and flag to check whether CRLs should be updated from CRL distribution point
    private String amAuthX509_updateCRL;
    private boolean doCRLUpdate = true;


    static {
        String handler = SystemProperties.get(Constants.PROTOCOL_HANDLER,
            Constants.JSSE_HANDLER);
        usingJSSHandler = handler.equals(Constants.JSS_HANDLER);
        if (usingJSSHandler) {
            JSSInit.initialize();
        }
    }

    /**
     * Default module constructor does nothing
     */
    public X509() {
    }

    /**
     * Initialize module
     * @param subject for auth
     * @param sharedState with auth framework
     * @param options for auth
     */
    public void init(Subject subject, Map sharedState, Map options) {
        if (debug == null) {
            debug = com.sun.identity.shared.debug.Debug.getInstance(amAuthX509);
        }
        java.util.Locale locale = getLoginLocale();
        bundle = amCache.getResBundle(amAuthX509, locale);

        this.callbackHandler = getCallbackHandler();
        this.options = options;
        if (debug.messageEnabled()) {
            debug.message("X509 Auth resbundle locale="+locale);
            debug.message("X509 auth init() done");
        }
    }

    private void initAuthConfig() throws AuthLoginException {
        if (options != null) {
            debug.message("Certificate: getting attributes.");
            // init auth level
            String authLevel = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-auth-level");
            if (authLevel != null) {
                try {
                    int tmp = Integer.parseInt(authLevel);
                    setAuthLevel(tmp);
                } catch (Exception e) {
                    // invalid auth level
                    debug.error("Invalid auth level " + authLevel, e);
                }
            }
            // will need access control to ldap server; passwd and user name
            // will also need to yank out the user profile based on cn or dn
            //  out of "profile server"
            amAuthX509_securityType = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-security-type");
            amAuthX509_principleUser = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-principal-user");
               amAuthX509_principlePasswd = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-principal-passwd");
            amAuthX509_useSSL = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-use-ssl");
            amAuthX509_userProfileMapper = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-user-profile-mapper");
            amAuthX509_altUserProfileMapper = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-user-profile-mapper-other");
            amAuthX509_subjectAltExtMapper = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-user-profile-mapper-ext");
            amAuthX509_chkCRL = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-check-crl");
            if (amAuthX509_chkCRL.equalsIgnoreCase("true")) {
                amAuthX509_chkAttrCRL = CollectionHelper.getMapAttr(
                    options, "iplanet-am-auth-x509-attr-check-crl");
                if (amAuthX509_chkAttrCRL == null ||
                    amAuthX509_chkAttrCRL.equals("")) {
                    throw new AuthLoginException(amAuthX509, "noCRLAttr", null);
                } else {
                    amAuthX509_chkAttributesCRL = trimItems(amAuthX509_chkAttrCRL.split(","));
                }
                amAuthX509_cacheCRL = CollectionHelper.getMapAttr(
                        options, "openam-am-auth-x509-attr-cache-crl","true");
                if (amAuthX509_cacheCRL.equalsIgnoreCase("false")) {
                    doCRLCaching = false;
                }
                amAuthX509_updateCRL = CollectionHelper.getMapAttr(
                        options, "openam-am-auth-x509-update-crl", "true");
                if (amAuthX509_updateCRL.equalsIgnoreCase("false")) {
                    doCRLUpdate = false;
                }

                crlEnabled = true;
            }
            amAuthX509_validateCA = CollectionHelper.getMapAttr(
                options, "sunAMValidateCACert");

            amAuthX509_uriParamsCRL = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-param-get-crl");
            amAuthX509_chkCertInLDAP = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-check-cert-in-ldap");
            if (amAuthX509_chkCertInLDAP.equalsIgnoreCase("true")) {
                amAuthX509_chkAttrCertInLDAP = CollectionHelper.getMapAttr(
                    options, "iplanet-am-auth-x509-attr-check-ldap");
                if (amAuthX509_chkAttrCertInLDAP == null ||
                    amAuthX509_chkAttrCertInLDAP.equals("")) {
                    throw new AuthLoginException(
                        amAuthX509, "noLDAPAttr", null);
                }
            }
            String ocspChk = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-check-ocsp");
            ocspEnabled = (ocspChk != null && ocspChk.equalsIgnoreCase("true"));

             //
            //  portal-style gateway cert auth enabled if
            //  explicitly specified in cert service template.
            //  "none", empty list, or null means disabled;
            //  "any" or non-empty list means enabled.  also check
            //  non-empty list for remote client's addr.
            //
            String gwCertAuth = CollectionHelper.getMapAttr(
                options, "iplanet-am-auth-x509-gw-cert-auth-enabled");
            certParamName = CollectionHelper.getMapAttr(
                options,"sunAMHttpParamName");

            String client = getLoginState("process").getClient();
            portal_gw_cert_auth_enabled = false;
            if (gwCertAuth == null || gwCertAuth.equals("")
                                || gwCertAuth.equalsIgnoreCase("none")) {
                if (debug.messageEnabled()) {
                    debug.message("iplanet-am-auth-x509-gw-cert-auth-enabled = "
                        + gwCertAuth);
                }
            } else if (gwCertAuth.equalsIgnoreCase("any")) {
                portal_gw_cert_auth_enabled = true;
            } else {
                portalGateways =
                  (Set)options.get("iplanet-am-auth-x509-gw-cert-auth-enabled");
                if ((client !=null) && (portalGateways.contains(client))) {
                    portal_gw_cert_auth_enabled = true;
                } else {
                    if (debug.messageEnabled()) {
                        debug.message("gateway list does not contain client");
                        Iterator clientIter = portalGateways.iterator();
                        while (clientIter.hasNext()) {
                            String clientStr = (String)clientIter.next();
                            debug.message("client list entry = " + clientStr);
                        }
                    }
                 }
            }

            amAuthX509_emailAddrTag = bundle.getString("emailAddrTag");

            amAuthX509_serverHost = CollectionHelper.getServerMapAttr(
                options, "iplanet-am-auth-x509-ldap-provider-url");
            if (amAuthX509_serverHost == null
                && (amAuthX509_chkCertInLDAP.equalsIgnoreCase("true") ||
                    amAuthX509_chkCRL.equalsIgnoreCase("true"))) {
                debug.error("Fatal error: LDAP Server and Port misconfigured");
                throw new AuthLoginException(amAuthX509,
                                "wrongLDAPServer", null);
            }

            if (amAuthX509_serverHost != null) {
                // set LDAP Parameters
                try {
                    LDAPUrl ldapUrl = LDAPUrl.valueOf("ldap://"+amAuthX509_serverHost);
                    amAuthX509_serverPort = ldapUrl.getPort();
                    amAuthX509_serverHost = ldapUrl.getHost();
                } catch (Exception e) {
                    throw new AuthLoginException(amAuthX509, "wrongLDAPServer",
                        null);
                }
            }

            amAuthX509_startSearchLoc = CollectionHelper.getServerMapAttr(
                options, "iplanet-am-auth-x509-start-search-loc");
            if (amAuthX509_startSearchLoc == null
                && (amAuthX509_chkCertInLDAP.equalsIgnoreCase("true") ||
                    amAuthX509_chkCRL.equalsIgnoreCase("true"))) {
                debug.error("Fatal error: LDAP Start Search " +
                                "DN is not configured");
                throw new AuthLoginException(amAuthX509, "wrongStartDN", null);
            }

            if (amAuthX509_startSearchLoc != null) {
                if (!LDAPUtils.isDN(amAuthX509_startSearchLoc)) {
                    throw new AuthLoginException(amAuthX509, "wrongStartDN", null);
                }
            }

            if (debug.messageEnabled()) {
                debug.message("\nldapProviderUrl="+ amAuthX509_serverHost +
                    "\n\tamAuthX509_serverPort = " + amAuthX509_serverPort +
                    "\n\tstartSearchLoc=" + amAuthX509_startSearchLoc +
                    "\n\tsecurityType=" + amAuthX509_securityType +
                    "\n\tprincipleUser=" + amAuthX509_principleUser +
                    "\n\tauthLevel="+authLevel+
                    "\n\tuseSSL=" + amAuthX509_useSSL +
                    "\n\tocspEnable=" + ocspEnabled +
                    "\n\tuserProfileMapper=" + amAuthX509_userProfileMapper +
                    "\n\tsubjectAltExtMapper=" +
                        amAuthX509_subjectAltExtMapper +
                    "\n\taltUserProfileMapper=" +
                        amAuthX509_altUserProfileMapper +
                    "\n\tchkCRL=" + amAuthX509_chkCRL +
                    "\n\tchkAttrCRL=" + amAuthX509_chkAttrCRL +
                    "\n\tchkAttributesCRL=" + Arrays.toString(amAuthX509_chkAttributesCRL) +
                    "\n\tcacheCRL=" + doCRLCaching +
                    "\n\tupdateCRLs=" + doCRLUpdate +
                    "\n\tchkCertInLDAP=" + amAuthX509_chkCertInLDAP +
                    "\n\tchkAttrCertInLDAP=" + amAuthX509_chkAttrCertInLDAP +
                    "\n\temailAddr=" + amAuthX509_emailAddrTag +
                    "\n\tgw-cert-auth-enabled="+portal_gw_cert_auth_enabled +
                    "\n\tclient=" + client);
            }
        } else {
            debug.error("options is null");
            throw new AuthLoginException(amAuthX509, "CERTex", null);
        }
    }

    /**
     * Process Certificate based auth request
     * @param callbacks for auth
     * @param state with auth framework
     * @return proper jaas state for auth framework
     * @throws AuthLoginException if auth fails
     */
    public int process (Callback[] callbacks, int state)
        throws AuthLoginException {
        initAuthConfig();
        X509Certificate[] allCerts = null;
        try {
            HttpServletRequest servletRequest = getHttpServletRequest();

            if(debug.messageEnabled()){
            	 Enumeration<String> headerNames = servletRequest.getHeaderNames();
            	 debug.message ("Inicio");
                 if (headerNames != null) {
      			   while (headerNames.hasMoreElements()) {
      				   String headerName = headerNames.nextElement();
      				   try{
      					   debug.message ("Header ("+ headerName+ ")");
      					   debug.message ("Header ("+ headerName+ ") Value: " + servletRequest.getHeader(headerNames.nextElement()));
      				   }
      				   catch (Exception e){
      					 debug.error("Certificate:  headers with exception", e);
      				   }
      			   }

      			 debug.message ("Fim");
                 }
            }

            if (servletRequest != null) {
                allCerts = (X509Certificate[]) servletRequest.
                   getAttribute("javax.servlet.request.X509Certificate");
                if (allCerts == null || allCerts.length == 0) {
                    debug.message(
                          "Certificate: checking for cert passed in the URL.");
                    if (!portal_gw_cert_auth_enabled) {
                        debug.error ("Certificate: cert passed " +
                                     "in URL not enabled for this client");
                        throw new AuthLoginException(amAuthX509,
                            "noURLCertAuth", null);
                    }

                    thecert = getPortalStyleCert(servletRequest);
                    allCerts = new X509Certificate[] { thecert };
                } else {
                    if (debug.messageEnabled()) {
                        debug.message("Certificate: got all certs from " +
                            "HttpServletRequest =" + allCerts.length);
                    }
                    thecert = allCerts[0];
                }
            } else {
                thecert = sendCallback();
            }

            if (thecert == null) {
                debug.message("Certificate: no cert passed in.");
                throw new AuthLoginException(amAuthX509, "noCert", null);
            }

            // moved this call from the bottom to here so that url redirection
            // can work.
            getTokenFromCert(thecert);
            storeUsernamePasswd(userTokenId, null);
            if(debug.messageEnabled()){
                debug.message("in Certificate. userTokenId=" +
                    userTokenId + " from getTokenFromCert");
            }
        } catch (AuthLoginException e) {
            setFailureID(userTokenId);
            debug.error("Certificate:  exiting validate with exception", e);
            throw new AuthLoginException(amAuthX509, "noCert", null);
        }

        /* debug statements added for cgi. */
        if (debug.messageEnabled()) {
            debug.message("Got client cert =\n" + thecert.toString());
        }

        if (amAuthX509_chkCertInLDAP.equalsIgnoreCase("false") &&
                amAuthX509_chkCRL.equalsIgnoreCase("false") &&
                                !ocspEnabled) {
                return ISAuthConstants.LOGIN_SUCCEED;
        }

        /*
        * Based on the certificates presented, find the registered
        * (representation) of the certificate. If no certificates
        * match in the LDAP certificate directory return a failure
        * status.
        */
        if (ldapParam == null) {
            setLdapStoreParam();
        }

        if (amAuthX509_chkCertInLDAP.equalsIgnoreCase("true")) {
            X509Certificate ldapcert =
                AMCertStore.getRegisteredCertificate(
                    ldapParam, thecert, amAuthX509_chkAttrCertInLDAP);
            if (ldapcert == null) {
                debug.error("X509Certificate: getRegCertificate is null");
                setFailureID(userTokenId);
                throw new AuthLoginException(amAuthX509, "CertNoReg", null);
            }
        }

        int ret;
        if (usingJSSHandler) {
            ret = doJSSRevocationValidation(thecert);
        } else {
            ret = doJCERevocationValidation(allCerts);
        }

        if (ret != ISAuthConstants.LOGIN_SUCCEED) {
            debug.error("X509Certificate:CRL / OCSP verify failed.");
    	    setFailureID(userTokenId);
            throw new AuthLoginException(amAuthX509, "CertVerifyFailed", null);
        }

        return ISAuthConstants.LOGIN_SUCCEED;
    }

    private int doJSSRevocationValidation(X509Certificate cert) {
        int ret = ISAuthConstants.LOGIN_IGNORE;
        boolean validateCA = amAuthX509_validateCA.equalsIgnoreCase("true");

        X509CRL crl = null;

        if (crlEnabled) {
            crl = AMCRLStore.getCRL(ldapParam, cert, amAuthX509_chkAttributesCRL);

            if ((crl != null) && (!crl.isRevoked(cert))) {
                ret = ISAuthConstants.LOGIN_SUCCEED;
            }
        }

        /**
         * OCSP validation, this will use the CryptoManager.isCertvalid()
         * method to validate certificate, OCSP is one of the steps in
         * this process. Here is the algorith to find OCSP responder:
         * 1. use global OCSP responder if set
         * 2. use the OCSP responder in user's certificate if presents
         * 3. no OCSP responder
         * The isCertValid() WON'T perform OCSP validation if no OCSP responder
         * found in above process.
         */
        if (ocspEnabled) {
            try {
                CryptoManager cm = CryptoManager.getInstance();
                if (cm.isCertValid(cert.getEncoded(), true,
                    CryptoManager.CertUsage.SSLClient) == true) {
                    debug.message("cert is valid");
                    ret = ISAuthConstants.LOGIN_SUCCEED;
                } else {
                    ret = ISAuthConstants.LOGIN_IGNORE;
                }
            } catch (Exception e) {
                debug.message("certValidation failed with exception",e);
            }
        }
        if ((ret == ISAuthConstants.LOGIN_SUCCEED)
                && (crlEnabled || ocspEnabled)
                && validateCA
                && !AMCertStore.isRootCA(cert)) {
            /*
            The trust anchor is not necessarily a certificate, but a public key (trusted) entry in the trust-store. Don't
            march up the chain unless the AMCertStore can actually return a non-null issuer certificate. If the issuer
            certificate is null, then the result of the previous doRevocationValidation invocation is the final answer.
             */
            X509Certificate issuerCertificate = AMCertStore.getIssuerCertificate(
                    ldapParam, cert, amAuthX509_chkAttrCertInLDAP);
            if (issuerCertificate != null) {
                ret = doJSSRevocationValidation(issuerCertificate);
            }
        }
        return ret;
    }

    private int doJCERevocationValidation(X509Certificate[] allCerts)
        throws AuthLoginException {
    	int ret = ISAuthConstants.LOGIN_IGNORE;

    	try {
            Vector crls = new Vector();
            for (X509Certificate cert : allCerts) {
                X509CRL crl = AMCRLStore.getCRL(ldapParam, cert, amAuthX509_chkAttributesCRL);
                if (crl != null) {
                    crls.add(crl);
                }
            }
            if (debug.messageEnabled()) {
                debug.message("Cert.doRevocationValidation: crls size = " +
                          crls.size());
                if (crls.size() > 0) {
                    debug.message("CRL = " + crls.toString());
                }
            }

            AMCertPath certpath = new AMCertPath(crls);
            if (!certpath.verify(allCerts, crlEnabled, ocspEnabled)) {
                debug.error("CertPath:verify failed.");
                return ret;
            } else {
                if (debug.messageEnabled()) {
                    debug.message("CertPath:verify success.");
                }
            }
            ret = ISAuthConstants.LOGIN_SUCCEED;
    	}catch (Exception e) {
            debug.error("Cert.doRevocationValidation: verify failed.", e);
    	}

        return ret;
    }

    private void setLdapStoreParam() throws AuthLoginException {
    /*
     * Setup the LDAP certificate directory service context for
     * use in verification of the users certificates.
     */
        try {
            ldapParam = AMCertStore.setLdapStoreParam(amAuthX509_serverHost,
                       amAuthX509_serverPort,
                       amAuthX509_principleUser,
                       amAuthX509_principlePasswd,
                       amAuthX509_startSearchLoc,
                       amAuthX509_uriParamsCRL,
                       amAuthX509_useSSL.equalsIgnoreCase("true"));

            ldapParam.setDoCRLCaching(doCRLCaching);
            ldapParam.setDoCRLUpdate(doCRLUpdate);

        } catch (Exception e) {
            debug.error("validate.SSLSocketFactory", e);
            setFailureID(userTokenId);
            throw new AuthLoginException(amAuthX509,"sslSokFactoryFail", null);
        }

        return;
    }

    private void getTokenFromCert(X509Certificate cert)
        throws AuthLoginException {
	if (!amAuthX509_subjectAltExtMapper.equalsIgnoreCase("none")) {
	    getTokenFromSubjectAltExt(cert);
	}

	if (!amAuthX509_userProfileMapper.equalsIgnoreCase("none") &&
	    (userTokenId == null)) {
	    getTokenFromSubjectDN(cert);
	}
    }

    private void getTokenFromSubjectAltExt(X509Certificate cert)
        throws AuthLoginException {
        try {
            X509CertImpl certImpl =
                new X509CertImpl(cert.getEncoded());
            X509CertInfo cinfo =
                new X509CertInfo(certImpl.getTBSCertificate());
            CertificateExtensions exts = (CertificateExtensions)
                            cinfo.get(X509CertInfo.EXTENSIONS);
            SubjectAlternativeNameExtension altNameExt =
                (SubjectAlternativeNameExtension)
                    exts.get(SubjectAlternativeNameExtension.NAME);

            if (altNameExt != null) {
                GeneralNames names = (GeneralNames) altNameExt.get
                    (SubjectAlternativeNameExtension.SUBJECT_NAME);

                GeneralName generalname = null;
                ObjectIdentifier upnoid = new ObjectIdentifier(UPNOID);
                ObjectIdentifier cpfoid = new ObjectIdentifier(CPFOID);
                ObjectIdentifier cnpjoid = new ObjectIdentifier(CNPJOID);

                Iterator itr = (Iterator) names.iterator();
                while ((userTokenId == null) && itr.hasNext()) {
                    generalname = (GeneralName) itr.next();
                    if (generalname != null) {
                        if ((amAuthX509_subjectAltExtMapper.
                        	equalsIgnoreCase("UPN") || amAuthX509_subjectAltExtMapper.
                        	equalsIgnoreCase("CPF") || amAuthX509_subjectAltExtMapper.
                        	equalsIgnoreCase("CNPJ")) &&
                        	(generalname.getType() ==
                	        GeneralNameInterface.NAME_ANY)) {
                            OtherName othername =
                                (OtherName)generalname.getName();

                            if (upnoid.equals((Object)(othername.getOID()))) {
                                byte[] nval = othername.getNameValue();
                                DerValue derValue = new DerValue(nval);
                                userTokenId =
                                    derValue.getData().getUTF8String();
                            }
                            else if (cpfoid.equals((Object)(othername.getOID()))) {
                                byte[] nval = othername.getNameValue();
                                DerValue derValue = new DerValue(nval);
                                byte[] octetString = derValue.getData().getOctetString();
                                String informacao = new String(octetString);
                                if(informacao.length() >= 19){
                                	userTokenId = informacao.substring(8, 19);
                                }
                            }
                            else if (cnpjoid.equals((Object)(othername.getOID()))) {
                            	byte[] nval = othername.getNameValue();
                            	DerValue derValue = new DerValue(nval);
                                byte[] octetString = derValue.getData().getOctetString();
                                String informacao = new String(octetString);
                                userTokenId = informacao;
                            }
                        }
                        else if (amAuthX509_subjectAltExtMapper.
                            equalsIgnoreCase("RFC822Name") &&
                            (generalname.getType() ==
                	        GeneralNameInterface.NAME_RFC822)) {
                            RFC822Name email =
                                (RFC822Name) generalname.getName();
                            userTokenId = email.getName();
                        }
                    }
                }
            }
        } catch (Exception e) {
            debug.error("Certificate - " +
                    "Error in getTokenFromSubjectAltExt = " , e);
            throw new AuthLoginException(amAuthX509, "CertNoReg", null);
        }

    }

    private void getTokenFromSubjectDN(X509Certificate cert)
        throws AuthLoginException {
    /*
     * The certificate has passed the authentication steps
     * so return the part of the certificate as specified
     * in the profile server.
     */
        try {
        /*
         * Get the Attribute value of the input certificate
         */
            X500Principal subjectPrincipal = cert.getSubjectX500Principal();
            if (debug.messageEnabled()) {
                debug.message("getTokenFromCert: Subject DN : " + CertUtils.getSubjectName(cert));
            }

            if (amAuthX509_userProfileMapper.equalsIgnoreCase("subject DN")) {
                userTokenId = CertUtils.getSubjectName(cert);
            } else if (amAuthX509_userProfileMapper.equalsIgnoreCase("subject UID")) {
                userTokenId = CertUtils.getAttributeValue(subjectPrincipal, CertUtils.UID);
            } else if (amAuthX509_userProfileMapper.equalsIgnoreCase("subject CN")) {
                userTokenId = CertUtils.getAttributeValue(subjectPrincipal, CertUtils.COMMON_NAME);
            } else if (amAuthX509_userProfileMapper.equalsIgnoreCase(amAuthX509_emailAddrTag)) {
                userTokenId = CertUtils.getAttributeValue(subjectPrincipal, CertUtils.EMAIL_ADDRESS);
                if (userTokenId == null) {
                    userTokenId = CertUtils.getAttributeValue(subjectPrincipal, CertUtils.MAIL);
                }
            } else if (amAuthX509_userProfileMapper.equalsIgnoreCase("DER Certificate")) {
                userTokenId = String.valueOf(cert.getTBSCertificate());
            } else if (amAuthX509_userProfileMapper.equals("other")) {
                //  "other" has been selected, so use attribute specified in the
                //  iplanet-am-auth-x509-user-profile-mapper-other attribute,
                //  which is in amAuthX509_altUserProfileMapper.
                userTokenId =  CertUtils.getAttributeValue(subjectPrincipal, amAuthX509_altUserProfileMapper);
            }

            if (debug.messageEnabled()) {
                debug.message("getTokenFromCert: " + amAuthX509_userProfileMapper + userTokenId);
            }
        } catch (Exception e) {
            if (debug.messageEnabled()) {
                debug.message("Certificate - Error in getTokenFromSubjectDN = " , e);
            }
            throw new AuthLoginException(amAuthX509, "CertNoReg", null);
        }
    }

    public java.security.Principal getPrincipal() {
        if (userPrincipal != null) {
            return userPrincipal;
        } else if (userTokenId != null) {
            userPrincipal = new X509AuthPrincipal(userTokenId);
            return userPrincipal;
        } else {
            return null;
        }
    }

    /**
     * Return value of Certificate
     * @return X509Certificate for auth
     */
    public X509Certificate getCertificate() {
       return thecert;
    }

    /**
     * Return value of Attribute Name for CRL checking
     * @return value for attribute name to search crl from ldap store
     */
    public String getChkAttrCRL() {
       return amAuthX509_chkAttrCRL;
    }

    /**
     * Return value of Debug object for this module
     *
     * @return debug
     */
    public com.sun.identity.shared.debug.Debug getDebug() {
       return debug;
    }

    /**
     * Return value of URI parameter for getting CRL
     *
     * @return value of URI parameter for getting CRL
     */
    public String getUriParamsCRL() {
       return amAuthX509_uriParamsCRL;
    }

    /**
     * Return value of LDAP Search loc for directory server
     *
     * @return value of LDAP Search loc for directory server
     */
    public String getStartSearchLoc() {
       return amAuthX509_startSearchLoc;
    }

    private X509Certificate sendCallback() throws AuthLoginException {
        if (callbackHandler == null) {
            throw new AuthLoginException(amAuthX509, "NoCallbackHandler", null);        }
        X509Certificate cert = null;
        try {
            Callback[] callbacks = new Callback[1];
            callbacks[0] =
                new X509CertificateCallback (bundle.getString("certificate"));
            callbackHandler.handle(callbacks);
            X509CertificateCallback xcb = (X509CertificateCallback)callbacks[0];
            /*
             * Allow Cert auth module accepts personal certificate only for
             * following 3 cases :
             * 1. portal_gw_cert_auth_enabled == true :
             *    Case of getting cert from trusted host like sra,
             *    distAuth, trusted LB
             * 2. xcb.getReqSignature() == false :
             *    Case of getting cert through ssl client auth enabled port
             * 3. (xcb.getReqSignature() == true) && (signature != null) :
             *    Case of getting cert together with signature from sdk client              */
            byte[] signature = xcb.getSignature();
            if (portal_gw_cert_auth_enabled ||
                !xcb.getReqSignature() ||
                (xcb.getReqSignature() && (signature != null))) {
                cert = xcb.getCertificate();
            }
            return cert;
        } catch (IllegalArgumentException ill) {
            debug.message("message type missing");
            throw new AuthLoginException(amAuthX509, "IllegalArgs", null);
        } catch (java.io.IOException ioe) {
            throw new AuthLoginException(ioe);
        } catch (UnsupportedCallbackException uce) {
            throw new AuthLoginException(amAuthX509, "NoCallbackHandler", null);
        }
    }

    private X509Certificate getPortalStyleCert (HttpServletRequest request)
       throws AuthLoginException {
       String certParam = null;

       if ((certParamName != null) && (certParamName.length() > 0)) {
           debug.message ("getPortalStyleCert: checking cert in HTTP header");
           StringTokenizer tok = new StringTokenizer(certParamName, ",");
           while (tok.hasMoreTokens()) {
               String key = tok.nextToken();
                certParam = request.getHeader(key);
                if (certParam == null) {
                    continue;
                }
                certParam = certParam.trim();
                String begincert = "-----BEGIN CERTIFICATE-----";
                String endcert = "-----END CERTIFICATE-----";
                int idx = certParam.indexOf(endcert);
                if (idx != -1) {
                    certParam = certParam.substring(begincert.length(), idx);
                    certParam = certParam.trim();
                }
           }
       } else {
           debug.message("getPortalStyleCert: checking cert in userCert param");
           Hashtable requestHash =
               getLoginState("getPortalStyleCert()").getRequestParamHash();
           if (requestHash != null) {
               certParam = (String) requestHash.get("IDToken0");
               if (certParam == null) {
                   certParam = (String) requestHash.get("Login.Token0");
               }
           }
       }

       if (debug.messageEnabled()) {
           debug.message ("in Certificate. validate certParam: " + certParam);
       }
       if (certParam == null || certParam.equals("")) {
           debug.message("Certificate: no cert from HttpServletRequest");
           throw new AuthLoginException(amAuthX509, "noCert", null);
       }

       byte[] decoded = Base64.decode(certParam);
       if (decoded == null) {
           debug.error("CertificateFromParameter(decode): failed, possibly invalid Base64 input");
           throw new AuthLoginException(amAuthX509, "CERTex", null);
       }
       InputStream carray = new ByteArrayInputStream(decoded);

       debug.message("Certificate: CertificateFactory.getInstance.");
       CertificateFactory cf = null;
       X509Certificate userCert = null;
       try {
           cf = CertificateFactory.getInstance("X.509");
           userCert = (X509Certificate) cf.generateCertificate(carray);
       } catch (Exception e) {
           debug.error("CertificateFromParameter(X509Cert): exception ", e);
           throw new AuthLoginException(amAuthX509, "CERTex", null);
       }

       if (userCert == null) {
           throw new AuthLoginException(amAuthX509, "CERTex", null);
       }

       if (debug.messageEnabled()) {
           debug.message("X509Certificate: principal is: " +
               userCert.getSubjectDN().getName() +
               "\nissuer DN:" + userCert.getIssuerDN().getName() +
               "\nserial number:" + String.valueOf(userCert.getSerialNumber()) +
               "\nsubject dn:" + userCert.getSubjectDN().getName());
        }
        return userCert;
    }

    /**
     * Destroy the state of module
     */
    public void destroyModuleState() {
        userPrincipal = null;
        userTokenId = null;
    }

    /**
     * Initialize all member variables as null
     */
    public void nullifyUsedVars() {
        bundle = null;
        thecert = null;
        options = null;
        callbackHandler = null;
        amAuthX509_serverHost = null;
        amAuthX509_startSearchLoc = null;
        amAuthX509_securityType = null;
        amAuthX509_principleUser = null;
        amAuthX509_principlePasswd = null;
        amAuthX509_useSSL = null;
        amAuthX509_userProfileMapper = null;
        amAuthX509_altUserProfileMapper = null;
        amAuthX509_chkCRL = null;
        amAuthX509_chkAttrCRL = null;
        amAuthX509_chkAttributesCRL = null;
        amAuthX509_uriParamsCRL = null;
        amAuthX509_chkCertInLDAP = null;
        amAuthX509_chkAttrCertInLDAP = null;
        amAuthX509_emailAddrTag = null;
        portalGateways = null;
        amAuthX509_updateCRL = null;
    }

    private String[] trimItems(String[] items) {
        String[] trimmedItems = new String[items.length];
        for (int i = 0; i < items.length; i++) {
            trimmedItems[i] = items[i].trim();
        }
        return trimmedItems;
    }
}
