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
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 *
 * @author shane
 */
public class SSLContextManager {

    /** SSLContext in use by ssl sockets. */
    private SSLContext sslContext = null;

    /** keyStore path. */
    private final String keyStore;

    /** keyStore password. */
    private final String storePassword;

    /** key password. */
    private final String keyPassword;

    /** Path to the PEM file containing public certificates. */
    private final String certificatePemFile;

    /** Path to the PEM file containing private keys. */
    private final String privateKeyPemFile;

    /**
     * Creates a new SSLContextManager that will read certificates from a keystore.
     *
     * @param keyStore keyStore path
     * @param storePassword keyStore password
     * @param keyPassword key password
     */
    public SSLContextManager(final String keyStore, final String storePassword, final String keyPassword) {
        this.keyStore =  keyStore;
        this.storePassword = storePassword;
        this.keyPassword = keyPassword;
        this.certificatePemFile = null;
        this.privateKeyPemFile = null;
    }

    /**
     * Creates a new SSLContextManager that will read certificates from PEM files.
     *
     * @param certificatePemFile Path to certificate pemfile
     * @param privateKeyPemFile Path to private key pemfile
     */
    public SSLContextManager(final String certificatePemFile, final String privateKeyPemFile) {
        this.keyStore = null;
        this.storePassword = null;
        this.keyPassword = "dummy";
        this.certificatePemFile = certificatePemFile;
        this.privateKeyPemFile = privateKeyPemFile;
    }

    /**
     * Set the SSLContext of this ContextManager.
     *
     * @param context new ssl context to use.
     */
    public synchronized void setSSLContext(final SSLContext context) {
        this.sslContext = context;
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
     * @throws InvalidKeySpecException If there is a problem with the ssl keys
     */
    public synchronized SSLContext getSSLContext()
            throws IllegalArgumentException, KeyStoreException, NoSuchAlgorithmException,
            KeyManagementException, UnrecoverableKeyException, IOException, CertificateException,
            InvalidKeySpecException {
        if (this.sslContext == null) {
            // Load the keystore
            final KeyStore ks = keyStore == null ? getKeyStoreFromPemFiles() : getKeyStoreFromDisk();

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

    /**
     * Get keystore from java keystore file on disk.
     *
     * @return Keystore from disk.
     * @throws NoSuchAlgorithmException If there is a problem getting the right algorithm for the SSLContext
     * @throws IOException If there is a problem opening the keystore
     * @throws CertificateException If there is a problem with the keystore
     */
    private KeyStore getKeyStoreFromDisk() throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        if (keyStore == null || keyStore.isEmpty()) {
            throw new IllegalArgumentException("No keystore specified.");
        } else if (storePassword == null || storePassword.isEmpty()) {
            throw new IllegalArgumentException("No keystore password specified.");
        } else if (keyPassword == null || keyPassword.isEmpty()) {
            throw new IllegalArgumentException("No key password specified.");
        }

        final File keyFile = new File(keyStore);
        if (!keyFile.exists()) { throw new FileNotFoundException("Keystore '"+keyStore+"' does not exist."); }

        final KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keyFile), storePassword.toCharArray());
        return ks;
    }

    /**
     * Get keystore from pem files.
     *
     * @return Keystore from pem files.
     * @throws KeyStoreException If there is a problem with the keystore
     * @throws NoSuchAlgorithmException If there is a problem getting the right algorithm for the SSLContext
     * @throws IOException If there is a problem opening the keystore
     * @throws CertificateException If there is a problem with the keystore
     * @throws InvalidKeySpecException If there is a problem with the ssl keys
     */
    private KeyStore getKeyStoreFromPemFiles() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, KeyStoreException {
        if (privateKeyPemFile == null || privateKeyPemFile.isEmpty()) {
            throw new IllegalArgumentException("No private key file specified.");
        } else if (certificatePemFile == null || certificatePemFile.isEmpty()) {
            throw new IllegalArgumentException("No certificate file specified.");
        }

        Security.addProvider(new BouncyCastleProvider());

        final PrivateKey privateKey = readPrivateKey();
        final X509Certificate[] certs = readCertificates();

        final KeyStore pemKeyStore = KeyStore.getInstance("JKS");
        pemKeyStore.load(null);
        pemKeyStore.setCertificateEntry("cert-alias", certs[0]);
        pemKeyStore.setKeyEntry("key-alias", privateKey, keyPassword.toCharArray(), certs);

        return pemKeyStore;
    }

    /**
     * Read the private key from disk
     *
     * @return PrivateKey
     * @throws IOException if we couldn't read the file.
     */
    private PrivateKey readPrivateKey() throws IOException {
        final PEMParser parser = new PEMParser(new InputStreamReader(new FileInputStream(privateKeyPemFile)));
        final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        Object obj;
        while ((obj = parser.readObject()) != null) {
            if (obj instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) obj);
            } else if (obj instanceof PEMKeyPair) {
                return converter.getPrivateKey(((PEMKeyPair) obj).getPrivateKeyInfo());
            }
        }

        throw new IOException("No private key found in '" + privateKeyPemFile + "'.");
    }

    /**
     * Read certificates from disk
     *
     * @return Array of X509Certificates from disk
     * @throws IOException if we couldn't read the file.
     * @throws CertificateException if there was a problem with the certificates.
     */
    private X509Certificate[] readCertificates() throws IOException, CertificateException {
        final List<X509Certificate> certs = new ArrayList<>();

        final PEMParser parser = new PEMParser(new InputStreamReader(new FileInputStream(certificatePemFile)));
        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

        Object obj;
        while ((obj = parser.readObject()) != null) {
            if (obj instanceof X509CertificateHolder) {
                certs.add(converter.getCertificate((X509CertificateHolder)obj));
            }
        }

        if (certs.isEmpty()) {
            throw new IOException("No certificates found in '" + certificatePemFile + "'.");
        }

        return certs.toArray(new X509Certificate[0]);
    }

}
