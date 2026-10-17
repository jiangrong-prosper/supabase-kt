import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.Auth
import io.github.jan.supabase.auth.AuthImpl
import io.github.jan.supabase.auth.MemorySessionManager
import io.github.jan.supabase.auth.SessionManager
import io.github.jan.supabase.auth.SessionImportResult
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
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
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
        val delegate = MemorySessionManager()
        var saved: UserSession? = null
        val storage = object : SessionManager by delegate {
            override suspend fun saveSession(session: UserSession) {
                delegate.saveSession(session)
                saved = session
            }
        }
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
                    CallbackObservation(delivered, client.auth.currentSessionOrNull(), client.auth.currentAccessTokenOrNull(), client.auth.sessionStatus.value, saved)
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
            val callbackStatus = observed.status as? SessionStatus.Authenticated
            assertTrue(
                observed.current == delivered && observed.accessToken == a.accessToken && callbackStatus?.session == delivered,
                "Recovery success callback ran before import: deliveredUser=${delivered.user?.id}, " +
                    "callbackCurrentUser=${observed.current?.user?.id}, callbackAccessOwner=${owner(observed.accessToken)}"
            )
            assertTrue(observed.saved == delivered)
            assertTrue(callbackStatus?.source == SessionSource.External)
        } finally {
            client.close()
        }
    }

    @Test
    fun recoveryImmediateRefreshCommitsBeforeCallback() = pendingRecovery(RecoveryBoundary.SUCCESS)

    @Test
    fun recoveryRefreshInvalidatedByNewAccount() = pendingRecovery(RecoveryBoundary.IMPORT)

    @Test
    fun recoveryRefreshInvalidatedBySignOut() = pendingRecovery(RecoveryBoundary.SIGN_OUT)

    @Test
    fun recoverySameAccountNewGenerationInvalidatesImport() = pendingRecovery(RecoveryBoundary.RELOGIN)

    @Test
    fun recoveryAuthenticationFailureCannotReportSuccess() = pendingRecovery(RecoveryBoundary.AUTH_FAILURE)

    @Test
    fun recoveryServerFailureRetriesAndCallsBackOnce() = pendingRecovery(RecoveryBoundary.RETRY)

    @Test
    fun recoveryNetworkFailureRetriesAndCallsBackOnce() = pendingRecovery(RecoveryBoundary.NETWORK_RETRY)

    @Test
    fun recoveryCancelledRefreshTerminatesWithoutSuccess() = pendingRecovery(RecoveryBoundary.CANCEL)

    @Test
    fun recoveryCommittedReceiptSurvivesJobReplacement() = pendingRecovery(RecoveryBoundary.JOB_REPLACEMENT)

    @Test
    fun recoveryCommittedReceiptSurvivesLaterRefresh() = pendingRecovery(RecoveryBoundary.LATER_REFRESH)

    @Test
    fun recoveryRepeatedPendingRefreshOnlyConfirmsFinalCommit() = pendingRecovery(RecoveryBoundary.PENDING_AGAIN)

    @Test
    fun recoveryRetryInvalidationTerminatesWithoutAnotherRequest() = pendingRecovery(RecoveryBoundary.RETRY_INVALIDATION)

    private enum class RecoveryBoundary {
        SUCCESS, IMPORT, SIGN_OUT, RELOGIN, AUTH_FAILURE, RETRY, NETWORK_RETRY,
        CANCEL, JOB_REPLACEMENT, LATER_REFRESH, PENDING_AGAIN, RETRY_INVALIDATION
    }

    private fun pendingRecovery(boundary: RecoveryBoundary) = runTest(timeout = 30.seconds) {
        // Exercise the public callback path and independently verify the internal terminal
        // receipt, including cancellation/invalidations that have no public success callback.
        for (recoveryCallback in listOf(true, false)) pendingRecovery(boundary, recoveryCallback)
    }

    private suspend fun TestScope.pendingRecovery(boundary: RecoveryBoundary, recoveryCallback: Boolean) {
        val original = session("A").copy(type = "recovery", expiresIn = 0, expiresAt = Instant.fromEpochMilliseconds(0))
        val before = session("B")
        val replacement = session(if (boundary == RecoveryBoundary.RELOGIN) "A" else "B").copy(
            accessToken = "sdk002-replacement-access", refreshToken = "sdk002-replacement-refresh"
        )
        val refreshed = session("A").copy(accessToken = "sdk002-refreshed-access", refreshToken = "sdk002-refreshed-refresh")
        val pendingAgain = original.copy(accessToken = "sdk002-pending-access", refreshToken = "sdk002-pending-refresh")
        val later = refreshed.copy(accessToken = "sdk002-later-access", refreshToken = "sdk002-later-refresh")
        val entered = List(2) { CompletableDeferred<Unit>() }
        val release = List(2) { CompletableDeferred<Unit>() }
        val saveEntered = CompletableDeferred<Unit>()
        val releaseSave = CompletableDeferred<Unit>()
        val delegate = MemorySessionManager()
        var saved: UserSession? = null
        var saves = 0
        val storage = object : SessionManager by delegate {
            override suspend fun saveSession(session: UserSession) {
                if (session.accessToken == refreshed.accessToken) {
                    saveEntered.complete(Unit)
                    releaseSave.await()
                }
                delegate.saveSession(session)
                saved = session
                saves++
            }
        }
        var requests = 0
        var lookups = 0
        var logouts = 0
        var callbacks = 0
        val callback = CompletableDeferred<CallbackObservation>()
        val client = controlledClient(storage, autoRefresh = true) { request ->
            when (request.url.pathAfterVersion()) {
                "/user" -> {
                    assertEquals(HttpMethod.Get, request.method)
                    assertTrue(request.headers["Authorization"] == "Bearer ${original.accessToken}")
                    lookups++
                    respondJson(requireNotNull(original.user))
                }
                "/logout" -> {
                    logouts++
                    respondJson(Unit)
                }
                "/token" -> {
                    assertEquals(HttpMethod.Post, request.method)
                    assertEquals("refresh_token", request.url.parameters["grant_type"])
                    val index = requests++
                    check(index < 2) { "Unexpected additional recovery refresh" }
                    val expectedToken = when {
                        index == 0 -> original.refreshToken
                        boundary == RecoveryBoundary.PENDING_AGAIN -> pendingAgain.refreshToken
                        boundary == RecoveryBoundary.LATER_REFRESH -> refreshed.refreshToken
                        else -> original.refreshToken
                    }
                    assertTrue(request.body.toJsonElement().jsonObject["refresh_token"]?.jsonPrimitive?.content == expectedToken)
                    entered[index].complete(Unit)
                    release[index].await()
                    when {
                        boundary == RecoveryBoundary.AUTH_FAILURE -> respondError(HttpStatusCode.BadRequest, """{"error_code":"session_not_found"}""")
                        boundary in listOf(RecoveryBoundary.RETRY, RecoveryBoundary.RETRY_INVALIDATION) && index == 0 -> respondError(HttpStatusCode.ServiceUnavailable, "{}")
                        boundary == RecoveryBoundary.NETWORK_RETRY && index == 0 -> throw IllegalStateException("Synthetic transport failure")
                        boundary == RecoveryBoundary.PENDING_AGAIN && index == 0 -> respondJson(pendingAgain)
                        boundary == RecoveryBoundary.LATER_REFRESH && index == 1 -> respondJson(later)
                        else -> respondJson(refreshed)
                    }
                }
                else -> error("Unexpected recovery endpoint")
            }
        }
        try {
            runCurrent()
            val auth = client.auth as AuthImpl
            auth.awaitInitialization()
            auth.importSession(before, autoRefresh = false, source = SessionSource.External)
            val receipt = if (recoveryCallback) {
                auth.parseFragmentAndImportSession(recoveryFragment(original)) { delivered ->
                    callbacks++
                    callback.complete(CallbackObservation(delivered, auth.currentSessionOrNull(), auth.currentAccessTokenOrNull(), auth.sessionStatus.value, saved))
                }
                null
            } else async { auth.importSessionWithAcknowledgement(original) }
            runCurrent()
            assertTrue(entered[0].isCompleted)
            assertTrue(lookups == if (recoveryCallback) 1 else 0)
            assertTrue(requests == 1 && callbacks == 0)
            assertFalse(callback.isCompleted)
            assertTrue(receipt?.isCompleted != true)
            assertTrue(auth.currentSessionOrNull() == before && saved == before)
            val initialJob = requireNotNull(auth.sessionJob)

            when (boundary) {
                RecoveryBoundary.IMPORT, RecoveryBoundary.RELOGIN -> auth.importSession(replacement, autoRefresh = false, source = SessionSource.External)
                RecoveryBoundary.SIGN_OUT -> auth.signOut()
                RecoveryBoundary.CANCEL -> auth.stopAutoRefreshForCurrentSession()
                else -> Unit
            }
            release[0].complete(Unit)
            runCurrent()
            val retries = boundary in listOf(RecoveryBoundary.RETRY, RecoveryBoundary.NETWORK_RETRY, RecoveryBoundary.RETRY_INVALIDATION)
            if (retries) {
                assertFalse(callback.isCompleted)
                assertTrue(receipt?.isCompleted != true)
                assertTrue(saves == 1 && requests == 1)
                if (boundary == RecoveryBoundary.RETRY_INVALIDATION) auth.importSession(replacement, autoRefresh = false, source = SessionSource.External)
                advanceTimeBy(auth.config.retryDelay.inWholeMilliseconds)
                runCurrent()
            }
            if (boundary in listOf(RecoveryBoundary.RETRY, RecoveryBoundary.NETWORK_RETRY, RecoveryBoundary.PENDING_AGAIN)) {
                assertTrue(entered[1].isCompleted)
                assertTrue(initialJob.isCancelled)
                assertFalse(callback.isCompleted)
                assertTrue(receipt?.isCompleted != true)
                assertTrue(saves == 1)
                release[1].complete(Unit)
                runCurrent()
            }
            val invalidated = boundary in listOf(RecoveryBoundary.IMPORT, RecoveryBoundary.RELOGIN, RecoveryBoundary.SIGN_OUT, RecoveryBoundary.RETRY_INVALIDATION)
            val failed = boundary in listOf(RecoveryBoundary.AUTH_FAILURE, RecoveryBoundary.CANCEL)
            if (invalidated || failed) {
                assertFalse(saveEntered.isCompleted)
                assertTrue(callbacks == 0 && !callback.isCompleted)
                if (receipt != null) {
                    assertTrue(receipt.isCompleted, "Terminal import must not leave its acknowledgement suspended")
                    if (invalidated) assertIs<SessionImportResult.Invalidated>(receipt.await())
                    else assertIs<SessionImportResult.NotCommitted>(receipt.await())
                }
                val cleared = boundary in listOf(RecoveryBoundary.SIGN_OUT, RecoveryBoundary.AUTH_FAILURE)
                val expected = if (cleared) null else if (boundary == RecoveryBoundary.CANCEL) before else replacement
                assertTrue(auth.currentSessionOrNull() == expected)
                assertTrue(storage.loadSessionOrNull() == expected)
                if (cleared) assertIs<SessionStatus.NotAuthenticated>(auth.sessionStatus.value)
                else assertTrue(assertIs<SessionStatus.Authenticated>(auth.sessionStatus.value).source == SessionSource.External)
                assertFalse(auth.isAutoRefreshRunning)
                assertTrue(requests == 1)
                assertTrue(logouts == if (boundary == RecoveryBoundary.SIGN_OUT) 1 else 0)
                return
            }

            // The response alone is insufficient: save is suspended and publication has
            // not happened. A callback/receipt at this point would be a false positive.
            assertTrue(saveEntered.isCompleted)
            assertTrue(auth.currentSessionOrNull() == before && saved == before)
            assertFalse(callback.isCompleted)
            assertTrue(receipt?.isCompleted != true)
            val observationTime = testScheduler.currentTime
            releaseSave.complete(Unit)
            runCurrent()
            val status = assertIs<SessionStatus.Authenticated>(auth.sessionStatus.value)
            assertTrue(status.session == refreshed && saved == refreshed)
            assertTrue(storage.loadSessionOrNull() == refreshed)
            val source = assertIs<SessionSource.Refresh>(status.source)
            assertTrue(source.oldSession.accessToken == if (boundary == RecoveryBoundary.PENDING_AGAIN) pendingAgain.accessToken else original.accessToken)
            assertTrue(initialJob.isCancelled)
            assertTrue(auth.isAutoRefreshRunning)
            assertTrue(auth.sessionJob !== initialJob)
            val committed = if (receipt != null) {
                assertTrue(receipt.isCompleted)
                assertIs<SessionImportResult.Committed>(receipt.await()).also {
                    assertTrue(it.refreshed && it.session == refreshed && it.source == status.source)
                }
            } else {
                assertTrue(callback.isCompleted && callbacks == 1)
                val observed = callback.await()
                assertTrue(observed.delivered == refreshed && observed.current == refreshed && observed.saved == refreshed)
                assertTrue(observed.accessToken == refreshed.accessToken && observed.status == status)
                null
            }
            if (boundary == RecoveryBoundary.JOB_REPLACEMENT) {
                val job = auth.sessionJob
                auth.startAutoRefreshForCurrentSession()
                runCurrent()
                assertTrue(auth.sessionJob !== job && job?.isCancelled == true && auth.isAutoRefreshRunning)
            }
            if (boundary == RecoveryBoundary.LATER_REFRESH) {
                val refreshing = async { auth.refreshCurrentSession() }
                runCurrent()
                assertTrue(entered[1].isCompleted)
                release[1].complete(Unit)
                runCurrent()
                assertTrue(refreshing.isCompleted)
                refreshing.await()
                assertTrue(auth.currentSessionOrNull() == later && storage.loadSessionOrNull() == later)
                assertIs<SessionSource.Refresh>(assertIs<SessionStatus.Authenticated>(auth.sessionStatus.value).source)
            }
            runCurrent()
            assertTrue(testScheduler.currentTime == observationTime)
            assertTrue(saves == if (boundary == RecoveryBoundary.LATER_REFRESH) 3 else 2)
            assertTrue(requests == if (boundary in listOf(RecoveryBoundary.RETRY, RecoveryBoundary.NETWORK_RETRY, RecoveryBoundary.PENDING_AGAIN, RecoveryBoundary.LATER_REFRESH)) 2 else 1)
            if (receipt != null) assertTrue(receipt.await() === committed)
            else assertTrue(callbacks == 1 && callback.await().delivered == refreshed)
        } finally {
            client.close()
        }
    }

    private fun recoveryFragment(session: UserSession) = "access_token=${session.accessToken}&refresh_token=${session.refreshToken}" +
        "&expires_in=${session.expiresIn}&token_type=${session.tokenType}&type=recovery"

    @Test
    fun recoveryInvalidFragmentKeepsNullCallback() = runTest(timeout = 30.seconds) {
        val storage = MemorySessionManager()
        var callbacks = 0
        val client = controlledClient(storage) { error("Invalid fragment must not perform HTTP") }
        try {
            runCurrent()
            client.auth.awaitInitialization()
            val before = client.auth.sessionStatus.value
            client.auth.parseFragmentAndImportSession("invalid") {
                callbacks++
                assertNull(it)
            }
            runCurrent()
            assertTrue(callbacks == 1 && client.auth.sessionStatus.value === before)
            assertNull(storage.loadSessionOrNull())
            assertFalse(client.auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    @Test
    fun recoveryUserQueryFailureCannotImport() = runTest(timeout = 30.seconds) {
        val storage = MemorySessionManager()
        var requests = 0
        var callbacks = 0
        val client = controlledClient(storage) {
            assertEquals("/user", it.url.pathAfterVersion())
            requests++
            respondError(HttpStatusCode.Unauthorized, "{}")
        }
        try {
            runCurrent()
            client.auth.awaitInitialization()
            val before = session("B")
            client.auth.importSession(before, source = SessionSource.External)
            val status = client.auth.sessionStatus.value
            client.auth.parseFragmentAndImportSession(recoveryFragment(session("A"))) { callbacks++ }
            runCurrent()
            assertTrue(requests == 1 && callbacks == 0)
            assertTrue(client.auth.currentSessionOrNull() == before && storage.loadSessionOrNull() == before)
            assertTrue(client.auth.sessionStatus.value === status)
            assertFalse(client.auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    @Test
    fun recoverySaveFailureCannotReportSuccess() = recoveryException(saveFailure = true)

    @Test
    fun recoveryCallbackExceptionDoesNotRepeatImportOrCallback() = recoveryException(saveFailure = false)

    private fun recoveryException(saveFailure: Boolean) = runTest(timeout = 30.seconds) {
        val expected = IllegalStateException("Synthetic recovery failure")
        val errors = mutableListOf<Throwable>()
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler) + CoroutineExceptionHandler { _, error -> errors.add(error) })
        val delegate = MemorySessionManager()
        var saves = 0
        var saved: UserSession? = null
        val storage = object : SessionManager by delegate {
            override suspend fun saveSession(session: UserSession) {
                saves++
                if (saveFailure && session.user?.id == "A") throw expected
                delegate.saveSession(session)
                saved = session
            }
        }
        var requests = 0
        var callbacks = 0
        var delivered: UserSession? = null
        val client = controlledClient(storage, scope = scope) {
            assertEquals("/user", it.url.pathAfterVersion())
            requests++
            respondJson(requireNotNull(session("A").user))
        }
        try {
            runCurrent()
            client.auth.awaitInitialization()
            val before = session("B")
            client.auth.importSession(before, source = SessionSource.External)
            val status = client.auth.sessionStatus.value
            client.auth.parseFragmentAndImportSession(recoveryFragment(session("A"))) {
                callbacks++
                delivered = it
                assertTrue(client.auth.currentSessionOrNull() == it && saved == it)
                throw expected
            }
            runCurrent()
            assertTrue(errors.size == 1 && errors.single() === expected)
            assertTrue(requests == 1 && saves == 2)
            if (saveFailure) {
                assertTrue(callbacks == 0 && delivered == null)
                assertTrue(client.auth.currentSessionOrNull() == before && delegate.loadSessionOrNull() == before)
                assertTrue(client.auth.sessionStatus.value === status)
            } else {
                assertTrue(callbacks == 1 && delivered?.user?.id == "A")
                assertTrue(client.auth.currentSessionOrNull() == delivered && delegate.loadSessionOrNull() == delivered)
                assertTrue(assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value).source == SessionSource.External)
            }
            runCurrent()
            assertTrue(errors.size == 1 && requests == 1 && saves == 2)
            assertTrue(callbacks == if (saveFailure) 0 else 1)
        } finally {
            client.close()
        }
    }

    @Test
    fun recoveryDirectReceiptsBelongToDistinctOperations() = runTest(timeout = 30.seconds) {
        val storage = MemorySessionManager()
        val client = controlledClient(storage) { error("Direct import must not perform HTTP") }
        try {
            runCurrent()
            val auth = client.auth as AuthImpl
            auth.awaitInitialization()
            val original = session("A")
            val first = assertIs<SessionImportResult.Committed>(auth.importSessionWithAcknowledgement(original))
            val second = assertIs<SessionImportResult.Committed>(auth.importSessionWithAcknowledgement(original))
            assertTrue(!first.refreshed && !second.refreshed)
            assertTrue(first.operationId !== second.operationId)
            assertTrue(first.session == original && second.session == original)
            assertTrue(first.source == SessionSource.External && second.source == SessionSource.External)
            assertTrue(auth.currentSessionOrNull() == original && storage.loadSessionOrNull() == original)
            assertFalse(auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    @Test
    fun recoveryRefreshedSaveFailureIsNotExternalInvalidation() = recoverySaveBoundary(cancel = false)

    @Test
    fun recoveryCancellationDuringSaveCannotConfirmCommit() = recoverySaveBoundary(cancel = true)

    private fun recoverySaveBoundary(cancel: Boolean) = runTest(timeout = 30.seconds) {
        val before = session("B")
        val original = session("A").copy(expiresIn = 0, expiresAt = Instant.fromEpochMilliseconds(0))
        val refreshed = session("A")
        val delegate = MemorySessionManager()
        val saveEntered = CompletableDeferred<Unit>()
        val releaseSave = CompletableDeferred<Unit>()
        var saves = 0
        val storage = object : SessionManager by delegate {
            override suspend fun saveSession(session: UserSession) {
                saves++
                if (session.user?.id == "A") {
                    saveEntered.complete(Unit)
                    if (cancel) releaseSave.await()
                    else throw IllegalStateException("Synthetic refreshed save failure")
                }
                delegate.saveSession(session)
            }
        }
        var requests = 0
        val client = controlledClient(storage, autoRefresh = true) {
            requests++
            respondJson(refreshed)
        }
        try {
            runCurrent()
            val auth = client.auth as AuthImpl
            auth.awaitInitialization()
            auth.importSession(before, autoRefresh = false, source = SessionSource.External)
            val status = auth.sessionStatus.value
            val waiting = async { auth.importSessionWithAcknowledgement(original) }
            runCurrent()
            assertTrue(saveEntered.isCompleted)
            if (cancel) {
                assertFalse(waiting.isCompleted)
                auth.stopAutoRefreshForCurrentSession()
                runCurrent()
            }
            assertTrue(waiting.isCompleted, "Save failure/cancellation must terminate the receipt")
            assertIs<SessionImportResult.NotCommitted>(waiting.await())
            if (!cancel) {
                // Preserve the existing retry policy; its old generation is no longer
                // current after the failed import, so it must not retry a stale save.
                advanceTimeBy(auth.config.retryDelay.inWholeMilliseconds)
                runCurrent()
            }
            releaseSave.complete(Unit)
            runCurrent()
            assertTrue(requests == 1 && saves == 2)
            assertTrue(auth.currentSessionOrNull() == before && delegate.loadSessionOrNull() == before)
            assertTrue(auth.sessionStatus.value === status)
            assertFalse(auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    @Test
    fun recoveryWaiterCancellationDoesNotCancelLegalImport() = runTest(timeout = 30.seconds) {
        val original = session("A").copy(expiresIn = 0, expiresAt = Instant.fromEpochMilliseconds(0))
        val refreshed = session("A")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val storage = MemorySessionManager()
        var requests = 0
        val client = controlledClient(storage, autoRefresh = true) {
            requests++
            entered.complete(Unit)
            release.await()
            respondJson(refreshed)
        }
        try {
            runCurrent()
            val auth = client.auth as AuthImpl
            auth.awaitInitialization()
            val waiting = async { auth.importSessionWithAcknowledgement(original) }
            runCurrent()
            assertTrue(entered.isCompleted)
            val job = requireNotNull(auth.sessionJob)
            waiting.cancel()
            runCurrent()
            assertTrue(waiting.isCancelled && job.isActive)
            release.complete(Unit)
            runCurrent()
            assertTrue(requests == 1)
            assertTrue(auth.currentSessionOrNull() == refreshed && storage.loadSessionOrNull() == refreshed)
            assertIs<SessionSource.Refresh>(assertIs<SessionStatus.Authenticated>(auth.sessionStatus.value).source)
            assertTrue(auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    @Test
    fun recoveryRetryFallbackConfirmsOriginalWithoutExtraSave() = runTest(timeout = 30.seconds) {
        val original = session("A").copy(expiresIn = 0, expiresAt = Instant.fromEpochMilliseconds(0))
        val before = session("B")
        val storage = MemorySessionManager()
        var requests = 0
        val client = controlledClient(storage) {
            requests++
            respondError(HttpStatusCode.ServiceUnavailable, "{}")
        }
        try {
            runCurrent()
            val auth = client.auth as AuthImpl
            auth.awaitInitialization()
            auth.importSession(before, source = SessionSource.External)
            // Explicit autoRefresh=true initially, existing config=false on retry.
            val waiting = async { auth.importSessionWithAcknowledgement(original, autoRefresh = true) }
            runCurrent()
            assertTrue(requests == 1 && !waiting.isCompleted)
            val job = requireNotNull(auth.sessionJob)
            advanceTimeBy(auth.config.retryDelay.inWholeMilliseconds)
            runCurrent()
            assertTrue(waiting.isCompleted && job.isCancelled)
            val result = assertIs<SessionImportResult.Committed>(waiting.await())
            assertTrue(!result.refreshed && result.session == original && result.source == SessionSource.External)
            assertTrue(auth.currentSessionOrNull() == original)
            // Existing no-auto-refresh rule does not save expiresIn=0 sessions.
            assertTrue(storage.loadSessionOrNull() == before)
            assertFalse(auth.isAutoRefreshRunning)
            assertTrue(requests == 1)
        } finally {
            client.close()
        }
    }

    @Test
    fun recoveryUnconfinedCallbackRunsOutsideCommitMutex() = runTest(timeout = 30.seconds) {
        val original = session("A").copy(expiresIn = 0)
        val refreshed = session("A")
        val replacement = session("B")
        val storage = MemorySessionManager()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val scope = CoroutineScope(SupervisorJob() + UnconfinedTestDispatcher(testScheduler))
        var callbacks = 0
        var reentrantImportCompleted = false
        val client = controlledClient(storage, autoRefresh = true, scope = scope) { request ->
            if (request.url.pathAfterVersion() == "/user") respondJson(requireNotNull(original.user))
            else {
                entered.complete(Unit)
                release.await()
                respondJson(refreshed)
            }
        }
        try {
            runCurrent()
            val auth = client.auth as AuthImpl
            auth.awaitInitialization()
            auth.parseFragmentAndImportSession(recoveryFragment(original)) { delivered ->
                callbacks++
                assertTrue(delivered == refreshed && auth.currentSessionOrNull() == refreshed)
                val importing = scope.launch(start = CoroutineStart.UNDISPATCHED) {
                    auth.importSession(replacement, autoRefresh = false, source = SessionSource.External)
                }
                reentrantImportCompleted = importing.isCompleted
            }
            runCurrent()
            assertTrue(entered.isCompleted && callbacks == 0)
            release.complete(Unit)
            runCurrent()
            assertTrue(callbacks == 1 && reentrantImportCompleted)
            assertTrue(auth.currentSessionOrNull() == replacement && storage.loadSessionOrNull() == replacement)
            assertFalse(auth.isAutoRefreshRunning)
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
        storage: SessionManager,
        requireSession: Boolean = false,
        jwtToken: String? = null,
        autoRefresh: Boolean = false,
        scope: CoroutineScope? = null,
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
                alwaysAutoRefresh = autoRefresh
                scope?.let { authScope = it }
                requireValidSession = requireSession
                this.jwtToken = jwtToken
            }
        })
    }

    private data class CallbackObservation(
        val delivered: UserSession?,
        val current: UserSession?,
        val accessToken: String?,
        val status: SessionStatus,
        val saved: UserSession?
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
