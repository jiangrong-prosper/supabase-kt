import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.Auth
import io.github.jan.supabase.auth.AuthImpl
import io.github.jan.supabase.auth.MemorySessionManager
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.auth.exception.SessionRequiredException
import io.github.jan.supabase.auth.parseFragmentAndImportSession
import io.github.jan.supabase.auth.status.SessionSource
import io.github.jan.supabase.auth.status.SessionStatus
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.auth.user.UserSession
import io.github.jan.supabase.exceptions.UnauthorizedRestException
import io.github.jan.supabase.logging.LogLevel
import io.github.jan.supabase.testing.createMockedSupabaseClient
import io.github.jan.supabase.testing.pathAfterVersion
import io.github.jan.supabase.testing.respondJson
import io.github.jan.supabase.testing.toJsonElement
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandler
import io.ktor.client.engine.mock.respondError
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** Security expectations intentionally expose the current production races. */
class Sdk002IdentityRaceTest {

    @Test
    fun staleUpdateResponseMustPreserveNewAccountSession() = updateResponse(switchAccount = true, updateCurrentUser = true)

    @Test
    fun normalUpdateChangesOnlyCurrentAccount() = updateResponse(switchAccount = false, updateCurrentUser = true)

    @Test
    fun updateWithoutLocalCommitPreservesNewAccountSession() = updateResponse(switchAccount = true, updateCurrentUser = false)

    private fun updateResponse(switchAccount: Boolean, updateCurrentUser: Boolean) = runTest(timeout = 30.seconds) {
        val a = session("A")
        val b = session("B")
        val updatedUser = requireNotNull(a.user).copy(email = "updated-a@example.invalid")
        val storage = MemorySessionManager()
        val requestEntered = CompletableDeferred<String?>()
        val releaseResponse = CompletableDeferred<Unit>()
        var requests = 0
        val client = controlledClient(storage) { request ->
            assertEquals(HttpMethod.Put, request.method)
            assertEquals("/user", request.url.pathAfterVersion())
            assertEquals(updatedUser.email, request.body.toJsonElement().jsonObject["email"]?.jsonPrimitive?.content)
            requests++
            requestEntered.complete(request.headers["Authorization"])
            releaseResponse.await()
            respondJson(updatedUser)
        }
        try {
            runCurrent()
            client.auth.awaitInitialization()
            client.auth.importSession(a, source = SessionSource.External)
            val update = async {
                client.auth.updateUser(updateCurrentUser = updateCurrentUser) { email = updatedUser.email }
            }
            runCurrent()
            assertTrue(requestEntered.isCompleted)
            val authorization = requestEntered.await()
            assertTrue(authorization == "Bearer ${a.accessToken}")
            assertFalse(update.isCompleted)
            if (switchAccount) client.auth.importSession(b, source = SessionSource.External)
            val before = assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value)
            val beforeSession = if (switchAccount) b else a
            assertTrue(before.session == beforeSession)
            assertTrue(storage.loadSessionOrNull() == beforeSession)
            val observationTime = testScheduler.currentTime

            releaseResponse.complete(Unit)
            runCurrent()
            assertTrue(update.isCompleted)
            val returned = update.await()
            val current = client.auth.currentSessionOrNull()
            val persisted = storage.loadSessionOrNull()
            val status = assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value)
            println(
                "SDK002 update: requestOwner=${owner(authorization?.removePrefix("Bearer "))}; " +
                    "returnedUser=${returned.id}; currentUser=${current?.user?.id}; " +
                    "accessOwner=${owner(current?.accessToken)}; refreshOwner=${owner(current?.refreshToken)}; " +
                    "storedUser=${persisted?.user?.id}; storedAccessOwner=${owner(persisted?.accessToken)}; " +
                    "storedRefreshOwner=${owner(persisted?.refreshToken)}; source=${sourceName(status)}; " +
                    "autoRefresh=${client.auth.isAutoRefreshRunning}; requests=$requests"
            )
            assertTrue(testScheduler.currentTime == observationTime)
            assertTrue(requests == 1)
            assertTrue(returned == updatedUser)
            assertFalse(client.auth.isAutoRefreshRunning)
            val expected = if (!switchAccount && updateCurrentUser) a.copy(user = updatedUser) else beforeSession
            val expectedSource = if (!switchAccount && updateCurrentUser) {
                status.source is SessionSource.UserChanged
            } else {
                client.auth.sessionStatus.value === before
            }
            // Compare complete sessions, including both credentials and the fixed expiry.
            val currentMatches = current == expected
            val persistedMatches = persisted == expected
            assertTrue(
                currentMatches && persistedMatches && expectedSource,
                "Session identity isolation violated: expectedUser=${expected.user?.id}, " +
                    "currentUser=${current?.user?.id}, storedUser=${persisted?.user?.id}, " +
                    "currentMatches=$currentMatches, persistedMatches=$persistedMatches, sourceMatches=$expectedSource"
            )
        } finally {
            client.close()
        }
    }

    @Test
    fun recoveryCallbackMustObserveImportedSession() = recoveryCallback(existingAccount = true)

    @Test
    fun recoveryWithoutExistingSessionEventuallyImportsCompleteSession() = recoveryCallback(existingAccount = false)

    private fun recoveryCallback(existingAccount: Boolean) = runTest(timeout = 30.seconds) {
        val a = session("A").copy(type = "recovery")
        val b = session("B")
        val storage = MemorySessionManager()
        val lookupEntered = CompletableDeferred<String?>()
        val releaseLookup = CompletableDeferred<Unit>()
        val callback = CompletableDeferred<CallbackObservation>()
        var requests = 0
        var callbacks = 0
        val client = controlledClient(storage) { request ->
            assertEquals(HttpMethod.Get, request.method)
            assertEquals("/user", request.url.pathAfterVersion())
            requests++
            lookupEntered.complete(request.headers["Authorization"])
            releaseLookup.await()
            respondJson(requireNotNull(a.user))
        }
        try {
            runCurrent()
            client.auth.awaitInitialization()
            if (existingAccount) client.auth.importSession(b, source = SessionSource.External)
            val fragment = "access_token=${a.accessToken}&refresh_token=${a.refreshToken}" +
                "&expires_in=${a.expiresIn}&token_type=${a.tokenType}&type=recovery"
            client.auth.parseFragmentAndImportSession(fragment) { delivered ->
                callbacks++
                callback.complete(
                    CallbackObservation(delivered, client.auth.currentSessionOrNull(), client.auth.currentAccessTokenOrNull(), client.auth.sessionStatus.value)
                )
            }
            runCurrent()
            assertTrue(lookupEntered.isCompleted)
            val authorization = lookupEntered.await()
            assertTrue(authorization == "Bearer ${a.accessToken}")
            assertFalse(callback.isCompleted)
            val observationTime = testScheduler.currentTime
            releaseLookup.complete(Unit)
            runCurrent()
            assertTrue(callback.isCompleted)
            val observed = callback.await()
            val delivered = requireNotNull(observed.delivered)
            val current = client.auth.currentSessionOrNull()
            val persisted = storage.loadSessionOrNull()
            val status = assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value)
            println(
                "SDK002 callback: requestOwner=${owner(authorization?.removePrefix("Bearer "))}; " +
                    "deliveredUser=${delivered.user?.id}; deliveredAccessOwner=${owner(delivered.accessToken)}; " +
                    "callbackCurrentUser=${observed.current?.user?.id}; callbackAccessOwner=${owner(observed.accessToken)}; " +
                    "callbackSource=${sourceName(observed.status)}; finalUser=${current?.user?.id}; " +
                    "finalAccessOwner=${owner(current?.accessToken)}; finalRefreshOwner=${owner(current?.refreshToken)}; " +
                    "storedUser=${persisted?.user?.id}; storedAccessOwner=${owner(persisted?.accessToken)}; " +
                    "finalSource=${sourceName(status)}; requests=$requests; callbacks=$callbacks"
            )
            assertTrue(testScheduler.currentTime == observationTime)
            assertTrue(requests == 1 && callbacks == 1)
            assertTrue(delivered.user == a.user)
            assertTrue(delivered.accessToken == a.accessToken && delivered.refreshToken == a.refreshToken)
            assertTrue(delivered.expiresIn == a.expiresIn && delivered.tokenType == a.tokenType && delivered.type == a.type)
            // The fragment parser computes expiresAt internally. Capture its result once;
            // complete comparisons below include that exact expiry without recomputing it.
            assertTrue(current == delivered)
            assertTrue(persisted == delivered)
            assertTrue(status.source == SessionSource.External)
            assertFalse(client.auth.isAutoRefreshRunning)
            if (existingAccount) {
                val callbackStatus = observed.status as? SessionStatus.Authenticated
                assertTrue(
                    observed.current == delivered && observed.accessToken == a.accessToken && callbackStatus?.session == delivered,
                    "Recovery success callback ran before import: deliveredUser=${delivered.user?.id}, " +
                        "callbackCurrentUser=${observed.current?.user?.id}, callbackAccessOwner=${owner(observed.accessToken)}"
                )
            }
        } finally {
            client.close()
        }
    }

    @Test
    fun missingRequiredSessionRejectsUpdateBeforeHttp() = runTest(timeout = 30.seconds) {
        val storage = MemorySessionManager()
        var requests = 0
        val client = controlledClient(storage, requireSession = true) {
            requests++
            error("A session-required update must not reach the HTTP handler without a session")
        }
        try {
            runCurrent()
            client.auth.awaitInitialization()
            val before = client.auth.sessionStatus.value
            assertFailsWith<SessionRequiredException> {
                client.auth.updateUser { email = "updated-a@example.invalid" }
            }
            assertTrue(requests == 0)
            assertTrue(client.auth.sessionStatus.value === before)
            assertNull(client.auth.currentSessionOrNull())
            assertNull(storage.loadSessionOrNull())
            assertFalse(client.auth.isAutoRefreshRunning)
            println("SDK002 no-session strict: HTTP requests=0; currentUser=NONE; storedUser=NONE")
        } finally {
            client.close()
        }
    }

    @Test
    fun missingSessionUsesProjectKeyAndPreservesStateOnUnauthorizedResponse() = runTest(timeout = 30.seconds) {
        val storage = MemorySessionManager()
        var requests = 0
        var authorization: String? = null
        val client = controlledClient(storage) { request ->
            assertEquals(HttpMethod.Put, request.method)
            assertEquals("/user", request.url.pathAfterVersion())
            requests++
            authorization = request.headers["Authorization"]
            respondError(HttpStatusCode.Unauthorized, "{}")
        }
        try {
            runCurrent()
            client.auth.awaitInitialization()
            val before = client.auth.sessionStatus.value
            assertFailsWith<UnauthorizedRestException> {
                client.auth.updateUser { email = "updated-a@example.invalid" }
            }
            assertTrue(requests == 1)
            assertTrue(authorization == "Bearer project-anon-key")
            assertTrue(client.auth.sessionStatus.value === before)
            assertNull(client.auth.currentSessionOrNull())
            assertNull(storage.loadSessionOrNull())
            assertFalse(client.auth.isAutoRefreshRunning)
            println("SDK002 no-session default: requestOwner=PROJECT_KEY; mockResponse=401; currentUser=NONE; storedUser=NONE")
        } finally {
            client.close()
        }
    }

    @Test
    fun signedOutSessionMustNotBeRestoredByUserUpdate() = userUpdateBoundary(UpdateBoundary.SIGN_OUT)

    @Test
    fun sameAccountReloginMustRejectEarlierUserUpdate() = userUpdateBoundary(UpdateBoundary.RELOGIN)

    @Test
    fun sameAccountImportMustRejectEarlierUserUpdate() = userUpdateBoundary(UpdateBoundary.IMPORT)

    @Test
    fun sameAccountRefreshAllowsUserUpdateWithoutRevertingTokens() = userUpdateBoundary(UpdateBoundary.REFRESH)

    @Test
    fun refreshedUserDataMustNotBeRevertedByEarlierUpdate() = userUpdateBoundary(UpdateBoundary.REFRESH_WITH_NEW_USER)

    @Test
    fun staleUserUpdateMustPreserveNewAccountRefreshJob() = userUpdateBoundary(UpdateBoundary.SWITCH_WITH_AUTO_REFRESH)

    @Test
    fun newerUserUpdateMustNotBeRevertedByEarlierResponse() = userUpdateBoundary(UpdateBoundary.NEWER_UPDATE)

    @Test
    fun resolverCredentialOverrideMustNotUpdateUnboundSession() = userUpdateBoundary(UpdateBoundary.OVERRIDE_TOKEN)

    @Test
    fun sessionWithoutUserProfileCanAcceptBoundUserUpdate() = userUpdateBoundary(UpdateBoundary.WITHOUT_PROFILE)

    private enum class UpdateBoundary {
        SIGN_OUT, RELOGIN, IMPORT, REFRESH, REFRESH_WITH_NEW_USER,
        SWITCH_WITH_AUTO_REFRESH, NEWER_UPDATE, OVERRIDE_TOKEN, WITHOUT_PROFILE
    }

    private fun userUpdateBoundary(boundary: UpdateBoundary) = runTest(timeout = 30.seconds) {
        val a = session("A")
        val initial = if (boundary == UpdateBoundary.WITHOUT_PROFILE) a.copy(user = null) else a
        val updatedUser = requireNotNull(a.user).copy(email = "updated-a@example.invalid")
        val newerUser = requireNotNull(a.user).copy(email = "newer-a@example.invalid")
        val renewed = a.copy(
            accessToken = "sdk002-renewed-access-A",
            refreshToken = "sdk002-renewed-refresh-A",
            expiresAt = Instant.parse("2031-01-01T00:00:00Z"),
            user = if (boundary == UpdateBoundary.REFRESH_WITH_NEW_USER) newerUser else a.user
        )
        val overrideToken = if (boundary == UpdateBoundary.OVERRIDE_TOKEN) "sdk002-override-access-A" else null
        val storage = MemorySessionManager()
        val requestEntered = CompletableDeferred<String?>()
        val releaseResponse = CompletableDeferred<Unit>()
        var updates = 0
        var refreshes = 0
        var logouts = 0
        val client = controlledClient(storage, jwtToken = overrideToken) { request ->
            when (request.url.pathAfterVersion()) {
                "/user" -> {
                    assertEquals(HttpMethod.Put, request.method)
                    updates++
                    if (updates == 1) {
                        requestEntered.complete(request.headers["Authorization"])
                        releaseResponse.await()
                        respondJson(updatedUser)
                    } else {
                        assertTrue(boundary == UpdateBoundary.NEWER_UPDATE && updates == 2)
                        assertTrue(request.headers["Authorization"] == "Bearer ${a.accessToken}")
                        respondJson(newerUser)
                    }
                }
                "/token" -> {
                    assertEquals(HttpMethod.Post, request.method)
                    assertTrue(boundary == UpdateBoundary.REFRESH || boundary == UpdateBoundary.REFRESH_WITH_NEW_USER)
                    assertEquals("refresh_token", request.url.parameters["grant_type"])
                    assertTrue(request.body.toJsonElement().jsonObject["refresh_token"]?.jsonPrimitive?.content == a.refreshToken)
                    refreshes++
                    respondJson(renewed)
                }
                "/logout" -> {
                    assertEquals(HttpMethod.Post, request.method)
                    assertTrue(boundary == UpdateBoundary.SIGN_OUT || boundary == UpdateBoundary.RELOGIN)
                    assertTrue(request.headers["Authorization"] == "Bearer ${a.accessToken}")
                    logouts++
                    respondJson("{}")
                }
                else -> error("Unexpected request in user-update boundary test")
            }
        }
        try {
            runCurrent()
            client.auth.awaitInitialization()
            client.auth.importSession(initial, source = SessionSource.External)
            val update = async { client.auth.updateUser { email = updatedUser.email } }
            runCurrent()
            assertTrue(requestEntered.isCompleted)
            val authorization = requestEntered.await()
            assertTrue(authorization == "Bearer ${overrideToken ?: a.accessToken}")
            assertFalse(update.isCompleted)
            when (boundary) {
                UpdateBoundary.SIGN_OUT, UpdateBoundary.RELOGIN -> {
                    val logout = async { client.auth.signOut() }
                    runCurrent()
                    assertTrue(logout.isCompleted)
                    logout.await()
                    assertNull(client.auth.currentSessionOrNull())
                    assertNull(storage.loadSessionOrNull())
                    if (boundary == UpdateBoundary.RELOGIN) {
                        client.auth.importSession(renewed, source = SessionSource.External)
                    }
                }
                UpdateBoundary.IMPORT -> client.auth.importSession(renewed.copy(user = newerUser), source = SessionSource.External)
                UpdateBoundary.REFRESH, UpdateBoundary.REFRESH_WITH_NEW_USER -> {
                    val refresh = async { client.auth.refreshCurrentSession() }
                    runCurrent()
                    assertTrue(refresh.isCompleted)
                    refresh.await()
                    assertTrue(client.auth.currentSessionOrNull() == renewed)
                    assertTrue(storage.loadSessionOrNull() == renewed)
                    assertIs<SessionSource.Refresh>(assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value).source)
                }
                UpdateBoundary.SWITCH_WITH_AUTO_REFRESH -> client.auth.importSession(session("B"), autoRefresh = true, source = SessionSource.External)
                UpdateBoundary.NEWER_UPDATE -> {
                    val newer = async { client.auth.updateUser { email = newerUser.email } }
                    runCurrent()
                    assertTrue(newer.isCompleted)
                    assertTrue(newer.await() == newerUser)
                    assertTrue(client.auth.currentSessionOrNull() == a.copy(user = newerUser))
                }
                UpdateBoundary.OVERRIDE_TOKEN, UpdateBoundary.WITHOUT_PROFILE -> Unit
            }
            runCurrent()
            val before = client.auth.sessionStatus.value
            val beforeSession = client.auth.currentSessionOrNull()
            val beforeStored = storage.loadSessionOrNull()
            val auth = client.auth as AuthImpl
            val refreshJob = auth.sessionJob
            val refreshInformation = auth.autoRefreshInformation()
            if (boundary == UpdateBoundary.SWITCH_WITH_AUTO_REFRESH) assertTrue(refreshJob?.isActive == true)
            val observationTime = testScheduler.currentTime
            releaseResponse.complete(Unit)
            runCurrent()
            assertTrue(update.isCompleted)
            assertTrue(update.await() == updatedUser)
            assertTrue(testScheduler.currentTime == observationTime)
            assertTrue(updates == if (boundary == UpdateBoundary.NEWER_UPDATE) 2 else 1)
            assertTrue(refreshes == if (boundary == UpdateBoundary.REFRESH || boundary == UpdateBoundary.REFRESH_WITH_NEW_USER) 1 else 0)
            assertTrue(logouts == if (boundary == UpdateBoundary.SIGN_OUT || boundary == UpdateBoundary.RELOGIN) 1 else 0)
            val accept = boundary == UpdateBoundary.REFRESH || boundary == UpdateBoundary.WITHOUT_PROFILE
            val expected = if (accept) requireNotNull(beforeSession).copy(user = updatedUser) else beforeSession
            val current = client.auth.currentSessionOrNull()
            val persisted = storage.loadSessionOrNull()
            println(
                "SDK002 boundary=$boundary; requestMatchesCapturedCredential=${authorization == "Bearer ${a.accessToken}"}; " +
                    "currentUser=${current?.user?.id}; localCommitAllowed=$accept; currentMatches=${current == expected}; " +
                    "storedMatches=${persisted == expected}; source=${sourceName(client.auth.sessionStatus.value)}; " +
                    "refreshJobPreserved=${auth.sessionJob === refreshJob}"
            )
            assertTrue(current == expected)
            assertTrue(persisted == if (accept) expected else beforeStored)
            if (accept) {
                assertIs<SessionSource.UserChanged>(assertIs<SessionStatus.Authenticated>(auth.sessionStatus.value).source)
            } else {
                assertTrue(auth.sessionStatus.value === before)
                assertTrue(auth.sessionJob === refreshJob)
                assertTrue(auth.autoRefreshInformation() == refreshInformation)
            }
            assertTrue(auth.isAutoRefreshRunning == (boundary == UpdateBoundary.SWITCH_WITH_AUTO_REFRESH))
        } finally {
            client.close()
        }
    }

    private fun TestScope.controlledClient(
        storage: MemorySessionManager,
        requireSession: Boolean = false,
        jwtToken: String? = null,
        handler: MockRequestHandler
    ): SupabaseClient {
        val testDispatcher = StandardTestDispatcher(testScheduler)
        return createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE
            coroutineDispatcher = testDispatcher
            httpEngine = MockEngine.create {
                dispatcher = testDispatcher
                addHandler(handler)
            }
            install(Auth) {
                sessionManager = storage
                autoLoadFromStorage = false
                autoSaveToStorage = true
                alwaysAutoRefresh = false
                requireValidSession = requireSession
                this.jwtToken = jwtToken
            }
        })
    }

    private data class CallbackObservation(
        val delivered: UserSession?,
        val current: UserSession?,
        val accessToken: String?,
        val status: SessionStatus
    )

    private fun session(account: String) = UserSession(
        accessToken = "sdk002-access-$account",
        refreshToken = "sdk002-refresh-$account",
        expiresIn = 3600,
        tokenType = "Bearer",
        user = UserInfo(id = account, aud = "authenticated", email = "$account@example.invalid"),
        expiresAt = Instant.parse("2030-01-01T00:00:00Z")
    )

    private fun owner(token: String?): String = when (token) {
        "sdk002-access-A", "sdk002-refresh-A" -> "A"
        "sdk002-access-B", "sdk002-refresh-B" -> "B"
        "project-anon-key" -> "PROJECT_KEY"
        null -> "NONE"
        else -> "UNEXPECTED"
    }

    private fun sourceName(status: SessionStatus): String = when (status) {
        is SessionStatus.Authenticated -> when (status.source) {
            SessionSource.External -> "External"
            is SessionSource.UserChanged -> "UserChanged"
            else -> "OTHER_AUTHENTICATED_SOURCE"
        }
        is SessionStatus.NotAuthenticated -> "NotAuthenticated"
        else -> "OTHER_STATUS"
    }
}
