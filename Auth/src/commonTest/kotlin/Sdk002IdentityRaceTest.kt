import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.Auth
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

    private fun TestScope.controlledClient(
        storage: MemorySessionManager,
        requireSession: Boolean = false,
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
