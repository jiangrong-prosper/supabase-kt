import io.github.jan.supabase.auth.Auth
import io.github.jan.supabase.auth.MemorySessionManager
import io.github.jan.supabase.auth.SessionManager
import io.github.jan.supabase.auth.SignOutScope
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.auth.exception.AuthSessionMissingException
import io.github.jan.supabase.auth.status.SessionSource
import io.github.jan.supabase.auth.status.SessionStatus
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.auth.user.UserSession
import io.github.jan.supabase.logging.LogLevel
import io.github.jan.supabase.testing.createMockedSupabaseClient
import io.github.jan.supabase.testing.respondJson
import io.ktor.client.engine.mock.respondError
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class AuthRefreshAuthorityTest {

    @Test
    fun sameAccountImportInvalidatesOldRefresh() = importDuringRefresh(sameAccount = true)

    @Test
    fun signOutCannotBeUndoneByOldRefresh() = importDuringRefresh(signOut = true)

    @Test
    fun staleSessionMissingErrorCannotClearImportedSession() = importDuringRefresh(missing = true)

    @Test
    fun staleServerErrorCannotChangeImportedSession() = importDuringRefresh(serverError = true)

    @Test
    fun laterManualRefreshInvalidatesEarlierResponse() = concurrentRefreshes()

    @Test
    fun laterManualRefreshSurvivesEarlierSessionMissingError() = concurrentRefreshes(missing = true)

    private fun concurrentRefreshes(missing: Boolean = false) = runTest(timeout = 30.seconds) {
        val storage = MemorySessionManager(session("B", "1"))
        val latest = session("B", "latest")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var requests = 0
        val client = createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE
            coroutineDispatcher = StandardTestDispatcher(testScheduler)
            install(Auth) { sessionManager = storage }
        }) {
            if (++requests == 1) {
                entered.complete(Unit)
                release.await()
                if (missing) respondError(HttpStatusCode.BadRequest, """{"error_code":"session_not_found"}""")
                else respondJson(session("B", "earlier"))
            } else respondJson(latest)
        }
        try {
            client.auth.awaitInitialization()
            val earlier = async { runCatching { client.auth.refreshCurrentSession() } }
            entered.await()
            client.auth.refreshCurrentSession()
            val status = client.auth.sessionStatus.value
            release.complete(Unit)
            val result = earlier.await()
            runCurrent()
            if (missing) assertIs<AuthSessionMissingException>(result.exceptionOrNull())
            else assertTrue(result.isSuccess)
            assertTrue(client.auth.sessionStatus.value === status)
            assertTrue(client.auth.currentSessionOrNull() == latest)
            assertTrue(storage.loadSessionOrNull() == latest)
            assertTrue(client.auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    @Test
    fun currentSessionMissingErrorStillClearsSession() = runTest(timeout = 30.seconds) {
        val storage = MemorySessionManager(session("B", "1"))
        val client = createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE
            coroutineDispatcher = StandardTestDispatcher(testScheduler)
            install(Auth) { sessionManager = storage }
        }) { respondError(HttpStatusCode.BadRequest, """{"error_code":"session_not_found"}""") }
        try {
            client.auth.awaitInitialization()
            val failure = runCatching { client.auth.refreshCurrentSession() }.exceptionOrNull()
            assertIs<AuthSessionMissingException>(failure)
            assertIs<SessionStatus.NotAuthenticated>(client.auth.sessionStatus.value)
            assertNull(storage.loadSessionOrNull())
            assertFalse(client.auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    private fun importDuringRefresh(
        sameAccount: Boolean = false,
        signOut: Boolean = false,
        missing: Boolean = false,
        serverError: Boolean = false
    ) = runTest(timeout = 30.seconds) {
        val original = session("B", "1")
        val replacement = session(if (sameAccount) "B" else "A", "new")
        val storage = MemorySessionManager(original)
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val client = createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE
            coroutineDispatcher = StandardTestDispatcher(testScheduler)
            install(Auth) { sessionManager = storage }
        }) { request ->
            if (request.url.encodedPath.endsWith("/logout")) {
                respondJson(Unit)
            } else {
                entered.complete(Unit)
                release.await()
                when {
                    missing -> respondError(HttpStatusCode.BadRequest, """{"error_code":"session_not_found"}""")
                    serverError -> respondError(HttpStatusCode.InternalServerError, "{}")
                    else -> respondJson(session("B", "old-response"))
                }
            }
        }
        try {
            client.auth.awaitInitialization()
            val refresh = async { runCatching { client.auth.refreshCurrentSession() } }
            entered.await()
            if (signOut) client.auth.signOut(SignOutScope.LOCAL) else client.auth.importSession(replacement)
            val statusAfterChange = client.auth.sessionStatus.value
            val refreshInfoAfterChange = client.auth.autoRefreshInformation()
            release.complete(Unit)
            val result = refresh.await()
            runCurrent() // Also execute any error-parser cleanup accidentally launched in authScope.
            if (missing) assertIs<AuthSessionMissingException>(result.exceptionOrNull())
            else if (serverError) assertTrue(result.isFailure)
            else assertTrue(result.isSuccess)
            assertTrue(client.auth.sessionStatus.value === statusAfterChange)
            // The new auto-refresh job may publish its own scheduled time.
            if (signOut) {
                assertNull(client.auth.currentSessionOrNull())
                assertNull(storage.loadSessionOrNull())
                assertFalse(client.auth.isAutoRefreshRunning)
                assertTrue(client.auth.autoRefreshInformation() == refreshInfoAfterChange)
            } else {
                assertTrue(client.auth.currentSessionOrNull() == replacement)
                assertTrue(storage.loadSessionOrNull() == replacement)
                assertTrue(client.auth.isAutoRefreshRunning)
                assertNull(client.auth.autoRefreshInformation()?.lastRefreshedAt)
            }
        } finally {
            client.close()
        }
    }

    @Test
    fun currentSessionRefreshCommitsMemoryStorageAndSource() = runTest(timeout = 30.seconds) {
        val original = session("B", "1")
        val refreshed = session("B", "2")
        val storage = MemorySessionManager(original)
        val client = createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE
            coroutineDispatcher = StandardTestDispatcher(testScheduler)
            install(Auth) { sessionManager = storage }
        }) { respondJson(refreshed) }
        try {
            client.auth.awaitInitialization()
            client.auth.refreshCurrentSession()
            val status = assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value)
            assertTrue(status.session == refreshed)
            assertTrue(storage.loadSessionOrNull() == refreshed)
            assertTrue(assertIs<SessionSource.Refresh>(status.source).oldSession == original)
            assertTrue(client.auth.isAutoRefreshRunning)
            assertTrue(client.auth.autoRefreshInformation()?.lastRefreshedAt != null)
        } finally {
            client.close()
        }
    }

    @Test
    fun automaticRefreshWinsOverEarlierManualRefresh() = runTest(timeout = 30.seconds) {
        val original = session("B", "1")
        val latest = session("B", "automatic")
        val storage = MemorySessionManager(original)
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var requests = 0
        val client = createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE
            coroutineDispatcher = StandardTestDispatcher(testScheduler)
            install(Auth) { sessionManager = storage }
        }) {
            requests++
            if (requests == 1) {
                entered.complete(Unit)
                release.await()
                respondJson(session("B", "manual-old"))
            } else {
                respondJson(latest)
            }
        }
        try {
            client.auth.awaitInitialization()
            val manual = launch { client.auth.refreshCurrentSession() }
            entered.await()
            advanceTimeBy(2_881_000) // Beyond the original session's 80% refresh deadline.
            runCurrent()
            assertTrue(requests == 2)
            assertTrue(client.auth.currentSessionOrNull() == latest)
            release.complete(Unit)
            manual.join()
            assertTrue(client.auth.currentSessionOrNull() == latest)
            assertTrue(storage.loadSessionOrNull() == latest)
            assertTrue(client.auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    @Test
    fun suspendedRefreshSaveAndNewImportAreSerialized() = runTest(timeout = 30.seconds) {
        val original = session("B", "1")
        val refreshed = session("B", "2")
        val replacement = session("A", "1")
        val delegate = MemorySessionManager(original)
        val saving = CompletableDeferred<Unit>()
        val releaseSave = CompletableDeferred<Unit>()
        val storage = object : SessionManager by delegate {
            override suspend fun saveSession(session: UserSession) {
                if (session == refreshed) {
                    saving.complete(Unit)
                    releaseSave.await()
                }
                delegate.saveSession(session)
            }
        }
        val client = createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE
            coroutineDispatcher = StandardTestDispatcher(testScheduler)
            install(Auth) { sessionManager = storage }
        }) { respondJson(refreshed) }
        try {
            client.auth.awaitInitialization()
            val refresh = launch { client.auth.refreshCurrentSession() }
            saving.await()
            val importing = launch { client.auth.importSession(replacement) }
            runCurrent()
            assertFalse(importing.isCompleted)
            releaseSave.complete(Unit)
            refresh.join()
            importing.join()
            assertTrue(client.auth.currentSessionOrNull() == replacement)
            assertTrue(storage.loadSessionOrNull() == replacement)
            assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value)
        } finally {
            client.close()
        }
    }

    @Test
    fun expiredStorageSessionRefreshesDuringInitialization() = runTest(timeout = 30.seconds) {
        val refreshed = session("B", "2")
        val storage = MemorySessionManager(session("B", "1").copy(expiresIn = 0, expiresAt = kotlin.time.Instant.fromEpochMilliseconds(0)))
        val client = createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE
            coroutineDispatcher = StandardTestDispatcher(testScheduler)
            install(Auth) { sessionManager = storage }
        }) { respondJson(refreshed) }
        try {
            client.auth.awaitInitialization()
            assertTrue(client.auth.currentSessionOrNull() == refreshed)
            assertTrue(storage.loadSessionOrNull() == refreshed)
            assertTrue(client.auth.isAutoRefreshRunning)
        } finally {
            client.close()
        }
    }

    private fun session(account: String, revision: String) = UserSession(
        accessToken = "synthetic-access-$account-$revision",
        refreshToken = "synthetic-refresh-$account-$revision",
        expiresIn = 3600,
        tokenType = "Bearer",
        user = UserInfo(id = account, aud = "authenticated")
    )
}
