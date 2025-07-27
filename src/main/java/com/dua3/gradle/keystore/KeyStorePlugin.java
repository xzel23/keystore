package com.dua3.gradle.keystore;

import com.dua3.utility.crypt.AsymmetricAlgorithm;
import com.dua3.utility.crypt.CertificateUtil;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.crypt.KeyUtil;
import com.dua3.utility.text.TextUtil;

import org.gradle.api.Project;
import org.gradle.api.DefaultTask;
import org.gradle.api.Plugin;
import org.gradle.api.tasks.TaskAction;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * The {@code LicenseGradlePlugin} class implements a Gradle plugin that provides
 * a custom task to generate a signing keystore. The plugin registers the task
 * {@code createKeyStore} in the "build setup" group.
 * <p>
 * This plugin simplifies setup steps in a Gradle build process for systems
 * requiring signing artifacts.
 */
public class KeyStorePlugin implements Plugin<Project> {

    /**
     * Constructor.
     */
    public KeyStorePlugin() { /* nothing to do */ }

    @Override
    public void apply(Project project) {
        KeyStoreExtension extension = project.getExtensions()
                .create("keyStore", KeyStoreExtension.class);

        project.getTasks().register("createKeyStore", CreateTrialSigningKeyStoreTask.class, task -> {
            task.setGroup("build setup");
            task.setDescription("Generates a short-lived signing keystore");
            task.setExtension(extension);
        });

        project.getTasks().register("createKeyStore", CreateTrialSigningKeyStoreTask.class, task -> {
            task.setGroup("build setup");
            task.setDescription("Generates a short-lived signing keystore");
        });
    }

    /**
     * Represents a task for generating a trial signing keystore. This task creates a
     * keystore with a short-lived trial signing certificate. It supports two modes of operation:
     * <p>
     * 1. CI mode, which uses developer keys and certificates from environment variables.
     * 2. Local mode, which uses a developer keystore file.
     * <p>
     * The generated trial keystore is stored as a Java KeyStore (JKS) file and includes a
     * key pair, trial certificate, and credentials necessary for signing operations.
     * Additionally, the developer's public certificate is written as a PEM resource.
     * <p>
     * Environment Variables:
     * - DEV_PRIVATE_KEY: Base64-encoded private key for developer (CI mode).
     * - DEV_CERT: Base64-encoded developer certificate in X.509 format (CI mode).
     * - TRIAL_KEYSTORE_PASSWORD: Password for the trial keystore.
     * - TRIAL_KEY_ALIAS: Alias for the trial key entry in the keystore.
     * - TRIAL_KEYSTORE_VALID_DAYS: Validity period (in days) for the trial certificate.
     * <p>
     * Task Behavior:
     * - CI Mode:
     *   - Uses developer private key and certificate from environment variables.
     *   - Fails if required variables are not present or invalid.
     * - Local Mode:
     *   - Uses a developer keystore file to load the private key and certificate.
     *   - Requires project-level configuration properties:
     *     - developer_keystore_path: Path to the keystore file.
     *     - developer_keystore_password: Password for the keystore file.
     *     - developer_keystore_developer_key_alias: Alias for the developer key in the keystore.
     * <p>
     * Outputs:
     * - The developer's certificate is saved in PEM format to `src/main/resources/keys/developer-cert.pem`.
     * - The trial signing keystore is stored as `src/main/resources/keys/trial-signing.jks`.
     * <p>
     * Task Registration:
     * This task can be registered in a Gradle project and invoked to generate the necessary keystore
     * required for development or testing purposes.
     */
    public abstract static class CreateTrialSigningKeyStoreTask extends DefaultTask {

        private KeyStoreExtension extension;

        /**
         * Sets the LicenseKeyStoreExtension instance for configuration.
         *
         * @param extension the LicenseKeyStoreExtension instance to be set
         */
        public void setExtension(KeyStoreExtension extension) {
            this.extension = extension;
        }

        /**
         * Generates a keystore with a trial key and certificate signer. It retrieves and processes
         * security-related information, such as private keys, certificates, and passwords, from
         * environment variables or specified file-based keystores.
         *
         * @throws GeneralSecurityException if there are issues related to security operations, such as
         *                                  generating keys or certificates.
         * @throws IOException if an input/output error occurs during file or keystore operations.
         */
        @TaskAction
        public void generateKeyStore() throws GeneralSecurityException, IOException {
            PrivateKey developerPrivateKey = KeyUtil.toPrivateKey(extension.getDeveloperPrivateKey(), AsymmetricAlgorithm.RSA);
            X509Certificate developerCertificate = CertificateUtil.toX509Certificate(TextUtil.base64Decode(extension.getParentCertBase64().get()));

            // Write developer public certificate as a PEM resource for embedding
            Path parentCertPath = extension.getParentCertDestination().get();
            Files.createDirectories(Objects.requireNonNull(parentCertPath.getParent()));
            try (Writer writer = Files.newBufferedWriter(parentCertPath, StandardCharsets.UTF_8)) {
                writer.write("-----BEGIN CERTIFICATE-----\n");
                writer.write(TextUtil.base64Encode(developerCertificate.getEncoded()).replaceAll("(.{64})", "$1\n"));
                writer.write("\n-----END CERTIFICATE-----\n");
            }
            getLogger().lifecycle("📄 Developer certificate written to: " + parentCertPath.toAbsolutePath());

            // Generate key pair for trial keystore
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair trialKeyPair = keyGen.generateKeyPair();


            int validDays = extension.getKeyStoreValidDays().get();
            X509Certificate[] trialCertificate = CertificateUtil.createX509Certificate(
                    trialKeyPair,
                    "CN=Trial License Issuer",
                    validDays,
                    developerCertificate,
                    developerPrivateKey
            );

            KeyStore keystore = KeyStoreUtil.createKeyStore(extension.getKeyStorePassword());
            keystore.setKeyEntry(
                    extension.getKeyAlias().get(),
                    trialKeyPair.getPrivate(),
                    extension.getKeyStorePassword(),
                    trialCertificate
            );

            Path keyStorePath = extension.getKeyStoreDestination().get();
            Files.createDirectories(Objects.requireNonNull(keyStorePath.getParent()));
            try (OutputStream fos = Files.newOutputStream(keyStorePath)) {
                keystore.store(fos, extension.getKeyStorePassword());
            }

            getLogger().lifecycle("✅ KeyStore created at: " + keyStorePath.toAbsolutePath());
        }
    }
}
