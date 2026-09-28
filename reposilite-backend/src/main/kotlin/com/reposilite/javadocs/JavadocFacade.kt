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

package com.reposilite.javadocs

import com.reposilite.javadocs.api.JavadocPageRequest
import com.reposilite.javadocs.api.JavadocRawRequest
import com.reposilite.javadocs.api.JavadocRawResponse
import com.reposilite.javadocs.api.JavadocResponse
import com.reposilite.journalist.Journalist
import com.reposilite.journalist.Logger
import com.reposilite.maven.MavenFacade
import com.reposilite.maven.Repository
import com.reposilite.maven.RepositoryVisibility.PRIVATE
import com.reposilite.maven.api.VersionLookupRequest
import com.reposilite.plugin.api.Facade
import com.reposilite.shared.ErrorResponse
import com.reposilite.shared.notFound
import com.reposilite.shared.notFoundError
import com.reposilite.shared.internalServerError
import com.reposilite.shared.unauthorized
import com.reposilite.shared.unauthorizedError
import com.reposilite.storage.api.Location
import com.reposilite.token.AccessTokenIdentifier
import com.reposilite.token.AccessTokenFacade
import io.javalin.http.ContentType
import panda.std.Result
import panda.std.Result.supplyThrowing
import panda.std.asSuccess
import panda.utilities.StringUtils
import java.nio.file.Path
import java.net.URLEncoder
import java.nio.charset.StandardCharsets.UTF_8
import kotlin.io.path.exists
import kotlin.io.path.inputStream
import kotlin.io.path.notExists
import kotlin.io.path.readLines

private const val LATEST_PATTERN = "/latest"

class JavadocFacade internal constructor(
    private val journalist: Journalist,
    val mavenFacade: MavenFacade,
    private val accessTokenFacade: AccessTokenFacade,
    private val javadocFolder: Path,
    private val javadocContainerService: JavadocContainerService,
    private val viewingCapabilities: JavadocViewingCapabilities = JavadocViewingCapabilities(),
) : Journalist, Facade {

    private val supportedExtensions = mapOf(
        "html" to ContentType.TEXT_HTML,
        "css" to ContentType.TEXT_CSS,
        "js" to ContentType.TEXT_JS,
        "json" to ContentType.TEXT_JS,
        "png" to ContentType.IMAGE_PNG,
        "svg" to ContentType.IMAGE_SVG,
    )

    private data class JavadocPlainFile(
        val targetPath: Path,
        val extension: String,
        val contentType: ContentType
    )

    fun findJavadocPage(request: JavadocPageRequest): Result<JavadocResponse, ErrorResponse> =
        with (request) {
            mavenFacade.canAccessResource(accessToken, repository, gav)
                .flatMap { createPage(accessToken, repository, resolveGav(request)) }
                .onError { logger.error("Cannot extract javadoc: ${it.message} (${it.status})}") }
        }

    fun findRawJavadocResource(request: JavadocRawRequest): Result<JavadocRawResponse, ErrorResponse> =
        with (request) {
            val parts = resource.toString().split("/", limit = 3)
            val usesCapability = repository.visibility == PRIVATE && parts.first() == "_"
            val effectiveResource = if (usesCapability && parts.size == 3) Location.of(parts[2]) else resource
            val authorizedToken: Result<AccessTokenIdentifier?, ErrorResponse> =
                if (usesCapability) {
                    if (parts.size != 3) unauthorizedError()
                    else authorizeCapability(parts[1], repository, gav).map { it }
                } else {
                    mavenFacade.canAccessResource(accessToken, repository, gav).map { accessToken }
                }

            authorizedToken
                .flatMap { javadocContainerService.loadContainer(it, repository, gav) }
                .map { it.javadocUnpackPath.resolve(effectiveResource.toString()) }
                .filter({ it.exists() }, { notFound("Resource $resource not found") })
                .map {
                    JavadocRawResponse(
                        contentType = supportedExtensions[effectiveResource.getExtension()] ?: ContentType.APPLICATION_OCTET_STREAM,
                        content = it.inputStream()
                    )
                }
        }

    internal fun isCapabilityResource(resource: Location): Boolean =
        resource.toString().substringBefore('/') == "_"

    internal fun redirectPrivateRawHtml(request: JavadocRawRequest): Result<String, ErrorResponse> = with(request) {
        val documentGav = documentGav(resolveGav(JavadocPageRequest(accessToken, repository, gav)))
        mavenFacade.canAccessResource(accessToken, repository, documentGav)
            .flatMap { javadocContainerService.loadContainer(accessToken, repository, documentGav) }
            .filter({ it.javadocUnpackPath.resolve(resource.toString()).exists() }, { notFound("Resource $resource not found") })
            .flatMap { issueCapability(accessToken, repository, documentGav) }
            .map { privateRawUrl(repository, documentGav, it, resource) }
    }

    private fun authorizeCapability(id: String, repository: Repository, gav: Location): Result<AccessTokenIdentifier?, ErrorResponse> {
        val capability = viewingCapabilities.find(id, repository.name, gav) ?: return unauthorizedError()
        val token = accessTokenFacade.getAccessTokenDetailsById(capability.accessToken)?.accessToken
            ?.takeUnless { it.isExpired() }
            ?.takeIf { it.encryptedSecret == capability.encryptedSecret }
            ?: return unauthorizedError()
        return mavenFacade.canAccessResource(token.identifier, repository, gav)
            .mapErr { unauthorized() }
            .map { token.identifier }
    }

    private fun issueCapability(accessToken: AccessTokenIdentifier?, repository: Repository, gav: Location): Result<String, ErrorResponse> {
        val token = accessToken?.let { accessTokenFacade.getAccessTokenDetailsById(it)?.accessToken }
            ?.takeUnless { it.isExpired() }
            ?: return unauthorizedError()
        return viewingCapabilities.issue(token.identifier, token.encryptedSecret, repository.name, gav).asSuccess()
    }

    private fun documentGav(gav: Location): Location =
        if (gav.getExtension() in setOf("jar", "zip")) gav.getParent() else gav

    private fun privateRawUrl(repository: Repository, gav: Location, id: String, resource: Location): String =
        "/javadoc/${encodePath(repository.name)}/${encodePath(gav.toString())}/raw/_/$id/${encodePath(resource.toString())}"

    private fun encodePath(path: String): String =
        path.split('/').joinToString("/") { URLEncoder.encode(it, UTF_8).replace("+", "%20") }

    private fun privateViewerHtml(html: String, url: String): Result<JavadocResponse, ErrorResponse> {
        val unpack = "/.cache/unpack/index.html"
        val iframe = "src=\"$unpack\""
        val script = "window.location.href + '$unpack'"
        val raw = "window.location.href + '/raw/index.html'"
        if (!html.contains(iframe) || !html.contains(script) || !html.contains(raw)) {
            return internalServerError("Unexpected cached Javadoc viewer")
        }
        return JavadocResponse(
            ContentType.HTML,
            html.replace(iframe, "src=\"$url\"")
                .replace(script, "'$url'")
                .replace(raw, "'$url'")
        ).asSuccess()
    }

    private fun createPage(accessToken: AccessTokenIdentifier?, repository: Repository, gav: Location): Result<JavadocResponse, ErrorResponse> {
        val resourcesFile = createPlainFile(javadocFolder, repository, gav)

        return when {
            /* File not found */
            resourcesFile != null && resourcesFile.targetPath.notExists() ->
                JavadocResponse(resourcesFile.contentType.mimeType, StringUtils.EMPTY).asSuccess()
            /* File exists */
            resourcesFile != null ->
                supplyThrowing {
                    JavadocResponse(resourcesFile.contentType.mimeType, readFile(resourcesFile.targetPath))
                }.mapErr {
                    notFound("Resource not found!")
                }
            /* Premature resources request */
            gav.contains("/resources/") ->
                notFoundError("Resources are unavailable before extraction")
            /* Load resource */
            else ->
                javadocContainerService
                    .loadContainer(accessToken, repository, gav)
                    .flatMap { container ->
                        val html = readFile(container.javadocContainerIndex)
                        if (repository.visibility != PRIVATE) {
                            JavadocResponse(ContentType.HTML, html).asSuccess()
                        } else {
                            val documentGav = documentGav(gav)
                            issueCapability(accessToken, repository, documentGav)
                                .flatMap { id -> privateViewerHtml(html, privateRawUrl(repository, documentGav, id, Location.of("index.html"))) }
                        }
                    }
        }
    }

    private fun createPlainFile(javadocFolder: Path, repository: Repository, gav: Location): JavadocPlainFile? =
        javadocFolder
            .resolve(repository.name)
            .resolve(gav.toString())
            .let { targetPath -> targetPath to supportedExtensions[gav.getExtension()] }
            .takeIf { (_, contentType) -> contentType != null }
            ?.let { (targetPath, contentType) -> JavadocPlainFile(targetPath, gav.getExtension(), contentType!!) }

    private fun readFile(indexFile: Path): String =
        indexFile.readLines().joinToString(separator = "\n")

    private fun resolveGav(request: JavadocPageRequest): Location =
        request.gav
            .takeIf { it.contains("/latest") }
            ?.let { request.gav.locationBeforeLast("/latest") }
            ?.let { gavWithoutVersion -> VersionLookupRequest(request.accessToken, request.repository, gavWithoutVersion) }
            ?.let { mavenFacade.findLatestVersion(it) }
            ?.map { request.gav.replace(LATEST_PATTERN, "/%s".format(it.version)) }
            ?.orNull()
            ?: request.gav

    override fun getLogger(): Logger =
        journalist.logger

}
