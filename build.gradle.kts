import org.gradle.internal.extensions.stdlib.toDefaultLowerCase
import java.net.URI

plugins {
    `java-gradle-plugin`
    `maven-publish`
}

description = "KeyStore Gradle Plugin"
version = "0.1.0-SNAPSHOT"

val scm = "https://github.com/xzel23/keystore"

val log4jVersion = "2.25.1"
val utilityVersion = "20.0.0-beta6-SNAPSHOT"
val bouncyCastleVersion = "1.81"


val isSnapshot = version.toString().toDefaultLowerCase().contains("-snapshot")

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    targetCompatibility = JavaVersion.VERSION_21
    sourceCompatibility = targetCompatibility

    withJavadocJar()
    withSourcesJar()
}

repositories {
    // Maven Central Repository
    mavenCentral()

    if (isSnapshot) {
        println("snapshot version detected, adding Maven snapshot repositories")

        // Sonatype Snapshots
        maven {
            name = "Central Portal Snapshots"
            url = URI("https://central.sonatype.com/repository/maven-snapshots/")
            mavenContent {
                snapshotsOnly()
            }
        }
    }
}

dependencies {
    implementation("org.apache.logging.log4j:log4j-api:$log4jVersion")
    implementation("com.dua3.utility:utility:$utilityVersion")
    runtimeOnly("org.bouncycastle:bcpkix-debug-jdk18on:$bouncyCastleVersion")

    // Test dependencies
    testImplementation(gradleTestKit())
}

gradlePlugin {
    website = scm
    vcsUrl = scm

    plugins {
        create("keystorePlugin") {
            id = "com.dua3.keystore"
            group = "com.dua3"
            displayName = "Plugin for creating a signing keystore at build time"
            description = "A plugin that generates a signing keystore at compile time."
            tags = listOf("java", "keystore", "security", "signing")
            implementationClass = "com.dua3.gradle.keystore.KeyStorePlugin"
        }
    }
}
