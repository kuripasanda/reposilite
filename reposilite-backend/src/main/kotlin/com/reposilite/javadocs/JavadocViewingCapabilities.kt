package com.reposilite.javadocs

import com.reposilite.storage.api.Location
import com.reposilite.token.AccessTokenIdentifier
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

internal data class JavadocViewingCapability(
    val accessToken: AccessTokenIdentifier,
    val encryptedSecret: String,
    val repository: String,
    val gav: Location,
    val issuedAt: Instant,
)

internal class JavadocViewingCapabilities(private val now: () -> Instant = Instant::now) {
    private val random = SecureRandom()
    private val entries = ConcurrentHashMap<String, JavadocViewingCapability>()
    private val lifetime = Duration.ofMinutes(30)

    // ponytail: process-local capabilities; use a shared store if requests must cross instances.
    fun issue(accessToken: AccessTokenIdentifier, encryptedSecret: String, repository: String, gav: Location): String {
        val issuedAt = now()
        entries.entries.removeIf { !issuedAt.isBefore(it.value.issuedAt.plus(lifetime)) }
        val id = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also(random::nextBytes))
        entries[id] = JavadocViewingCapability(accessToken, encryptedSecret, repository, gav, issuedAt)
        return id
    }

    fun find(id: String, repository: String, gav: Location): JavadocViewingCapability? {
        val capability = entries[id] ?: return null
        if (!now().isBefore(capability.issuedAt.plus(lifetime))) {
            entries.remove(id, capability)
            return null
        }
        return capability.takeIf { it.repository == repository && it.gav == gav }
    }
}