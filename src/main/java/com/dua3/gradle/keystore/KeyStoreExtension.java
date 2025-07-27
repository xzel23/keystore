package com.dua3.gradle.keystore;

import org.gradle.api.model.ObjectFactory;
import org.gradle.api.provider.Property;

import javax.inject.Inject;
import java.nio.file.Path;
import java.util.function.Supplier;

/**
 * Secure configuration extension for the License Gradle Plugin.
 * Only non-sensitive data is stored as Gradle properties.
 * Sensitive inputs (like private keys) must be provided at runtime via a supplier.
 */
public abstract class KeyStoreExtension {

    private Supplier<byte[]> privateKeySupplier = () -> {
        throw new IllegalStateException("supplier for private key isn't set");
    };

    private Supplier<char[]> keyStorePasswordSupplier = () -> {
        throw new IllegalStateException("supplier for keystore password isn't set");
    };

    @Inject
    public KeyStoreExtension(ObjectFactory objects) {
        this.parentCertBase64 = objects.property(String.class);
        this.keystoreValidDays = objects.property(Integer.class);
        this.keyAlias = objects.property(String.class);
        this.keyStoreDestination = objects.property(Path.class);
        this.parentCertDestination = objects.property(Path.class);
    }

    private final Property<String> parentCertBase64;
    private final Property<Integer> keystoreValidDays;
    private final Property<String> keyAlias;
    private final Property<Path> keyStoreDestination;
    private final Property<Path> parentCertDestination;

    // -- Getters for Gradle-safe configuration properties --

    public Property<String> getParentCertBase64() {
        return parentCertBase64;
    }

    public Property<Integer> getKeyStoreValidDays() {
        return keystoreValidDays;
    }

    public Property<String> getKeyAlias() {
        return keyAlias;
    }

    public Property<Path> getKeyStoreDestination() {
        return keyStoreDestination;
    }

    public Property<Path> getParentCertDestination() {
        return parentCertDestination;
    }

    // -- Sensitive input (keystore password and private key) --

    public void setKeyStorePasswordSupplier(Supplier<char[]> supplier) {
        this.keyStorePasswordSupplier = supplier;
    }

    public char[] getKeyStorePassword() {
        return keyStorePasswordSupplier.get();
    }

    /**
     * Set a supplier that provides the developer private key as a byte array at execution time.
     *
     * @param supplier the supplier function (e.g. reading from env vars or a secure vault)
     */
    public void setPrivateKeySupplier(Supplier<byte[]> supplier) {
        this.privateKeySupplier = supplier;
    }

    /**
     * Retrieves the developer private key as a byte array. The private key is provided
     * by a supplier function set at runtime.
     *
     * @return the developer private key as a byte array
     * @throws IllegalStateException if the supplier for the developer private key is not set
     */
    public byte[] getDeveloperPrivateKey() {
        return privateKeySupplier.get();
    }
}
