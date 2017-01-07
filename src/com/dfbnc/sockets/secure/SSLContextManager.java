/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.dfbnc.sockets.secure;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 *
 * @author shane
 */
public class SSLContextManager {
    /** SSLContext in use by ssl sockets */
    private SSLContext sslContext = null;

    /** keyStore path. */
    private final String keyStore;
    
    /** keyStore password. */
    private final String storePassword;
    
    /** key password. */
    private final String keyPassword;
    
    /**
     * Create a new SSLContextManager
     * 
     * @param keyStore keyStore path
     * @param storePassword keyStore password
     * @param keyPassword key password
     */
    public SSLContextManager(final String keyStore, final String storePassword, final String keyPassword) {
        this.keyStore =  keyStore;
        this.storePassword = storePassword;
        this.keyPassword = keyPassword;
    }
    
    /**
     * Get (and create if needed) a copy of the SSLContext we are using.
     *
     * @return SSLContext to use for new SSLEngines
     * @throws IllegalArgumentException If there is a problem with the settings related to ssl
     * @throws KeyStoreException If there is a problem with the keystore
     * @throws FileNotFoundException If the keystore does not exist
     * @throws NoSuchAlgorithmException If there is a problem getting the right algorithm for the SSLContext
     * @throws KeyManagementException If there is a problem with the keystore
     * @throws UnrecoverableKeyException  If there is a problem with the key in the keystore
     * @throws IOException If there is a problem opening the keystore
     * @throws CertificateException If there is a problem with the keystore
     */
    public synchronized SSLContext getSSLContext() throws IllegalArgumentException, KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, IOException, CertificateException {
        if (this.sslContext == null) {
            if (keyStore.isEmpty()) { throw new IllegalArgumentException("No keystore specified."); }
            else if (storePassword.isEmpty()) { throw new IllegalArgumentException("No keystore password specified."); }
            else if (keyPassword.isEmpty()) { throw new IllegalArgumentException("No key password specified."); }

            final File keyFile = new File(keyStore);
            if (!keyFile.exists()) { throw new FileNotFoundException("Keystore '"+keyStore+"' does not exist."); }
        
            // Load the keystore
            final KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keyFile), storePassword.toCharArray());

            // Load the keymanager
            final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keyPassword.toCharArray());

            // Load the TrustManager
            // TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            // tmf.init(ks);

            // Create an SSLContext
            sslContext = SSLContext.getInstance("TLS");

            // Init the SSL Context.
            //
            // We want to provide our own key using the key manager, and trust
            // all certificates sent so that we can see all certificates that
            // are given to us.
            sslContext.init(kmf.getKeyManagers(), TrustingTrustManager.getTrustingTrustManagers(), new SecureRandom());
        }

        return sslContext;
    }
    
}
