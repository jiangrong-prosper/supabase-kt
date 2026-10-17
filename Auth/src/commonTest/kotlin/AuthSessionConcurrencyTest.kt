import io.github.jan.supabase.auth.Auth
import io.github.jan.supabase.auth.MemorySessionManager
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.auth.status.SessionSource
import io.github.jan.supabase.auth.status.SessionStatus
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.auth.user.UserSession
import io.github.jan.supabase.logging.LogLevel
import io.github.jan.supabase.testing.createMockedSupabaseClient
import io.github.jan.supabase.testing.pathAfterVersion
import io.github.jan.supabase.testing.respondJson
import io.github.jan.supabase.testing.toJsonElement
import io.ktor.http.HttpMethod
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.concurrent.atomics.AtomicInt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class AuthSessionConcurrencyTest {

    @Test
    fun staleManualRefreshMustNotOverwriteNewlyImportedAccount() = runTest(timeout = 30.seconds) {
        val bInitial = session("B", "V1")
        val bRefreshed = session("B", "V2")
        val a = session("A", "V1")
        val storage = MemorySessionManager(bInitial)
        val refreshEntered = CompletableDeferred<Unit>()
        val releaseResponse = CompletableDeferred<Unit>()
        val bInitialRequests = AtomicInt(0)
        val aRequests = AtomicInt(0)
        val bRefreshedRequests = AtomicInt(0)
        val unexpectedRequests = AtomicInt(0)
        val client = createMockedSupabaseClient(configuration = {
            defaultLogLevel = LogLevel.NONE // Auth debug messages include complete sessions.
            coroutineDispatcher = StandardTestDispatcher(testScheduler)
            install(Auth) {
                sessionManager = storage
                // Retain default auto-load, auto-save, automatic refresh and cancellation.
            }
        }) { request ->
            assertEquals(HttpMethod.Post, request.method)
            assertEquals("/token", request.url.pathAfterVersion())
            assertEquals("refresh_token", request.url.parameters["grant_type"])
            val refreshToken = request.body.toJsonElement().jsonObject["refresh_token"]?.jsonPrimitive?.content
            when (refreshToken) {
                bInitial.refreshToken -> {
                    val count = bInitialRequests.fetchAndAdd(1) + 1
                    println("HTTP refresh identity=B-V1; count=$count; gated response=B-V2")
                    refreshEntered.complete(Unit)
                    releaseResponse.await() // Cancellable gate; no sleeps or cancellation suppression.
                    respondJson(bRefreshed)
                }
                a.refreshToken -> {
                    val count = aRequests.fetchAndAdd(1) + 1
                    println("HTTP refresh identity=A-V1; count=$count; response=A-V1 with renewed expiry")
                    respondJson(session("A", "V1"))
                }
                bRefreshed.refreshToken -> {
                    val count = bRefreshedRequests.fetchAndAdd(1) + 1
                    println("HTTP refresh identity=B-V2; count=$count; response=B-V2 with renewed expiry")
                    respondJson(session("B", "V2"))
                }
                else -> {
                    val count = unexpectedRequests.fetchAndAdd(1) + 1
                    println("HTTP refresh identity=UNEXPECTED; count=$count")
                    error("Unexpected synthetic refresh identity; raw token omitted")
                }
            }
        }
        try {
            client.auth.awaitInitialization()
            assertEquals("B", client.auth.currentUserOrNull()?.id)
            assertTrue(client.auth.isAutoRefreshRunning)
            println("1 B-V1 loaded through SDK storage initialization; auto-refresh active")

            // This public manual operation is owned by its caller, not the auto-refresh job.
            val oldRefresh = launch { client.auth.refreshCurrentSession() }
            refreshEntered.await()
            println("2 B refresh HTTP request entered; response suspended")

            client.auth.importSession(a)
            assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value)
            assertEquals("A", client.auth.currentUserOrNull()?.id)
            assertEquals("A", storage.loadSession().user?.id)
            assertTrue(client.auth.isAutoRefreshRunning)
            println("3 A-V1 authoritative in memory and SessionManager; auto-refresh active")

            releaseResponse.complete(Unit)
            oldRefresh.join()
            val finalSession = client.auth.currentSessionOrNull()
            val storedSession = storage.loadSessionOrNull()
            val source = assertIs<SessionStatus.Authenticated>(client.auth.sessionStatus.value).source
            println("4 B response released; operation completed=${oldRefresh.isCompleted}; cancelled=${oldRefresh.isCancelled}")
            println("5 final memory account=${finalSession?.user?.id}; SessionManager account=${storedSession?.user?.id}")
            println("6 B-V2 in memory=${finalSession == bRefreshed}; B-V2 in SessionManager=${storedSession == bRefreshed}")
            println("7 refresh source previous account=${(source as? SessionSource.Refresh)?.oldSession?.user?.id}")

            // Keep power-assert diagnostics restricted to a boolean, never Session objects.
            // A may legitimately renew its session; the invariant concerns account authority.
            val aRemainsAuthoritative = finalSession?.user?.id == "A" && storedSession?.user?.id == "A"
            assertEquals(0, unexpectedRequests.load(), "Unexpected refresh identities must be investigated")
            assertTrue(
                aRemainsAuthoritative,
                "Safety invariant violated: A must remain authoritative; memory=${finalSession?.user?.id}, SessionManager=${storedSession?.user?.id}, B refresh cancelled=${oldRefresh.isCancelled}"
            )
        } finally {
            client.close()
            println("Refresh totals: B-V1=${bInitialRequests.load()}; A-V1=${aRequests.load()}; B-V2=${bRefreshedRequests.load()}; UNEXPECTED=${unexpectedRequests.load()}")
            // runTest/JUnit reports uncaught asynchronous errors, including suppressed errors.
            // The test does not install an exception handler or suppress fixture failures.
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
