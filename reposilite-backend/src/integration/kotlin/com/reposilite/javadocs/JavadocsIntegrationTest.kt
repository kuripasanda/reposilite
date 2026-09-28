/*
 * Copyright (c) 2020-2026 dzikoysk
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@file:Suppress("FunctionName")

package com.reposilite.javadocs

import com.reposilite.RecommendedLocalSpecificationJunitExtension
import com.reposilite.RecommendedRemoteSpecificationJunitExtension
import com.reposilite.configuration.shared.SharedConfigurationFacade
import com.reposilite.javadocs.application.JavadocSettings
import com.reposilite.javadocs.specification.JavadocsIntegrationSpecification
import com.reposilite.storage.api.Location
import com.reposilite.token.AccessTokenFacade
import com.reposilite.token.Route
import com.reposilite.token.RoutePermission.READ
import com.reposilite.token.api.UpdateAccessTokenRequest
import io.javalin.http.HttpStatus.NOT_FOUND
import io.javalin.http.HttpStatus.UNAUTHORIZED
import java.net.HttpURLConnection
import java.net.URI
import java.time.Instant
import java.util.Base64
import kong.unirest.core.Unirest.get
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@ExtendWith(RecommendedLocalSpecificationJunitExtension::class)
internal class LocalJavadocsIntegrationTest : JavadocsIntegrationTest()

@ExtendWith(RecommendedRemoteSpecificationJunitExtension::class)
internal class RemoteJavadocsIntegrationTest : JavadocsIntegrationTest()

internal abstract class JavadocsIntegrationTest : JavadocsIntegrationSpecification() {

    @Test
    fun `private javadocs serve viewer html css and class pages through a scoped capability`() {
        val path = publishPrivateJavadoc()
        val (name, secret) = useAuth("javadoc-reader", "secret", routes = mapOf("/private/gav/reposilite" to READ))
        val viewer = get("$base$path").basicAuth(name, secret).asString()

        assertThat(viewer.status).isEqualTo(200)
        assertThat(viewer.headers.getFirst("Cache-Control")).isEqualTo("no-store")
        assertThat(viewer.headers.getFirst("Content-Security-Policy")).isEqualTo("sandbox allow-scripts")
        val index = Regex("""src="([^"]+/raw/_/[^\"]+/index\.html)"""").find(viewer.body)!!.groupValues[1]
        assertThat(viewer.body).contains("document.getElementById(\"javadoc\").src = '$index'")
        assertThat(viewer.body).contains("document.getElementById('raw').href = '$index'")
        assertThat(viewer.body).doesNotContain("/.cache/unpack/index.html")
        for (alias in listOf("latest", "3.0.0/reposilite-3.0.0-javadoc.jar")) {
            val aliasViewer = get("$base/javadoc/private/gav/reposilite/$alias").basicAuth(name, secret).asString()
            assertThat(aliasViewer.status).isEqualTo(200)
            assertThat(aliasViewer.body).contains("/javadoc/private/gav/reposilite/3.0.0/raw/_/")
        }

        val rawIndex = get("$base$index").asString()
        assertThat(rawIndex.status).isEqualTo(200)
        assertThat(rawIndex.headers.getFirst("Content-Security-Policy")).isEqualTo("sandbox allow-scripts")
        assertThat(rawIndex.headers.getFirst("Referrer-Policy")).isEqualTo("no-referrer")
        assertThat(rawIndex.headers.getFirst("Cache-Control")).isEqualTo("no-store")
        val rawRoot = index.removeSuffix("index.html")
        assertThat(get("$base${rawRoot}stylesheet.css").asString().status).isEqualTo(200)
        assertThat(get("$base${rawRoot}allclasses-index.html").asString().status).isEqualTo(200)
        assertThat(get("$base$path/raw/index.html").asString().status).isEqualTo(UNAUTHORIZED.code)
        assertThat(get("$base$path/raw/_/missing/index.html").asString().status).isEqualTo(UNAUTHORIZED.code)
        assertThat(get("$base${index.replace("/3.0.0/", "/4.0.0/")}").asString().status).isEqualTo(UNAUTHORIZED.code)

        val redirect = URI.create("$base$path/raw/index.html").toURL().openConnection() as HttpURLConnection
        redirect.instanceFollowRedirects = false
        redirect.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString("$name:$secret".toByteArray()))
        assertThat(redirect.responseCode).isEqualTo(302)
        assertThat(redirect.getHeaderField("Cache-Control")).isEqualTo("no-store")
        assertThat(redirect.getHeaderField("Location")).contains("/raw/_/")
        assertThat(get("$base${redirect.getHeaderField("Location")}").asString().status).isEqualTo(200)
        redirect.disconnect()
    }

    @Test
    fun `private javadoc capability stops working when its issuing token changes`() {
        val path = publishPrivateJavadoc()
        val route = Route("/private/gav/reposilite", READ)
        val (name, secret) = useAuth("javadoc-reader", "secret", routes = mapOf(route.path to READ))
        val tokens = useFacade<AccessTokenFacade>()
        val identifier = tokens.getAccessToken(name)!!.identifier
        fun issue(secret: String): String {
            val html = get("$base$path").basicAuth(name, secret).asString().body
            return Regex("""src="([^"]+/raw/_/[^\"]+/index\.html)"""").find(html)!!.groupValues[1]
        }

        val revokedRoute = issue(secret)
        tokens.deleteRoute(identifier, route)
        assertThat(get("$base$revokedRoute").asString().status).isEqualTo(UNAUTHORIZED.code)

        tokens.addRoute(identifier, route)
        val expiredToken = issue(secret)
        tokens.updateAccessToken(name, UpdateAccessTokenRequest(expiresAt = Instant.now().minusSeconds(1), updateExpiresAt = true))
        assertThat(get("$base$expiredToken").asString().status).isEqualTo(UNAUTHORIZED.code)

        tokens.updateAccessToken(name, UpdateAccessTokenRequest(updateExpiresAt = true))
        val rotatedSecret = issue(secret)
        tokens.regenerateAccessToken(tokens.getAccessTokenById(identifier)!!, "new-secret")
        assertThat(get("$base$rotatedSecret").asString().status).isEqualTo(UNAUTHORIZED.code)

        val deletedToken = issue("new-secret")
        tokens.deleteToken(identifier)
        assertThat(get("$base$deletedToken").asString().status).isEqualTo(UNAUTHORIZED.code)
    }

    private fun publishPrivateJavadoc(): String {
        val (repository, metadata) = useMetadata("private", "gav", "reposilite", listOf("3.0.0"))
        mavenFacade.getRepository(repository)!!.storageProvider.putFile(
            location = Location.of("${metadata.groupId}/${metadata.artifactId}/3.0.0/reposilite-3.0.0-javadoc.jar"),
            inputStream = JavadocsIntegrationTest::class.java.getResourceAsStream("/reposilite-javadoc.jar")!!,
        )
        return "/javadoc/private/gav/reposilite/3.0.0"
    }

    @Test
    fun `should serve javadocs`() {
        // given: some javadocs file & metadata file
        val (repository, metadata) = useMetadata(
            repository = "releases",
            groupId = "gav",
            artifactId = "reposilite",
            versions = listOf("3.0.0")
        )

        mavenFacade.getRepository(repository)!!
            .storageProvider
            .putFile(
                location = Location.of("${metadata.groupId}/${metadata.artifactId}/3.0.0/reposilite-3.0.0-javadoc.jar"),
                inputStream = JavadocsIntegrationTest::class.java.getResourceAsStream("/reposilite-javadoc.jar")!!
            )

        // when: client requests javadocs
        val response = get("$base/javadoc/releases/gav/reposilite/3.0.0")
            .asString()

        // then: response contains javadocs container
        assertThat(response.body).contains("""iframe id="javadoc"""")
    }

    @Test
    fun `should serve a non-javadoc suffix through the viewer`() {
        // given: an artifact published only with a groovydoc suffix (served by default)
        val (repository, metadata) = useMetadata(
            repository = "releases",
            groupId = "gav",
            artifactId = "reposilite",
            versions = listOf("3.0.0")
        )

        mavenFacade.getRepository(repository)!!
            .storageProvider
            .putFile(
                location = Location.of("${metadata.groupId}/${metadata.artifactId}/3.0.0/reposilite-3.0.0-groovydoc.jar"),
                inputStream = JavadocsIntegrationTest::class.java.getResourceAsStream("/reposilite-javadoc.jar")!!
            )

        // when: client requests javadocs through the directory url
        val response = get("$base/javadoc/releases/gav/reposilite/3.0.0")
            .asString()

        // then: response contains javadocs container
        assertThat(response.body).contains("""iframe id="javadoc"""")
    }

    @Test
    fun `should serve a non-jar extension when its suffix is configured`() {
        // given: a zip artifact and a configuration that serves the -docs.zip suffix
        val (repository, metadata) = useMetadata(
            repository = "releases",
            groupId = "gav",
            artifactId = "reposilite",
            versions = listOf("3.0.0")
        )

        mavenFacade.getRepository(repository)!!
            .storageProvider
            .putFile(
                location = Location.of("${metadata.groupId}/${metadata.artifactId}/3.0.0/reposilite-3.0.0-docs.zip"),
                inputStream = JavadocsIntegrationTest::class.java.getResourceAsStream("/reposilite-javadoc.jar")!!
            )

        useFacade<SharedConfigurationFacade>()
            .getDomainSettings<JavadocSettings>()
            .update(JavadocSettings(suffixes = listOf("-javadoc.jar", "-docs.zip")))

        // when: client requests javadocs through the directory url
        val response = get("$base/javadoc/releases/gav/reposilite/3.0.0")
            .asString()

        // then: response contains javadocs container
        assertThat(response.body).contains("""iframe id="javadoc"""")
    }

    @Test
    fun `should respond with not found when javadoc integration is disabled`() {
        // given: some javadocs file & metadata file with the javadoc integration disabled
        val (repository, metadata) = useMetadata(
            repository = "releases",
            groupId = "gav",
            artifactId = "reposilite",
            versions = listOf("3.0.0")
        )

        mavenFacade.getRepository(repository)!!
            .storageProvider
            .putFile(
                location = Location.of("${metadata.groupId}/${metadata.artifactId}/3.0.0/reposilite-3.0.0-javadoc.jar"),
                inputStream = JavadocsIntegrationTest::class.java.getResourceAsStream("/reposilite-javadoc.jar")!!
            )

        useFacade<SharedConfigurationFacade>()
            .getDomainSettings<JavadocSettings>()
            .update(JavadocSettings(enabled = false))

        // when: client requests javadocs
        val response = get("$base/javadoc/releases/gav/reposilite/3.0.0")
            .asString()

        // then: response is not found and does not leak the disabled state
        assertThat(response.status).isEqualTo(NOT_FOUND.code)
        assertThat(response.body).doesNotContain("disabled")
    }

}
