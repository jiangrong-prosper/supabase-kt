package io.github.jan.supabase.auth

import io.github.jan.supabase.annotations.SupabaseInternal
import io.github.jan.supabase.auth.status.SessionSource
import io.github.jan.supabase.auth.url.UrlValidationResult
import io.github.jan.supabase.auth.url.validateHash
import io.github.jan.supabase.auth.user.UserSession
import io.ktor.client.request.HttpRequestBuilder
import kotlinx.coroutines.launch

@SupabaseInternal
fun Auth.parseFragmentAndImportSession(fragment: String, onFinish: (UserSession?) -> Unit = {}) {
    val res = validateHash(fragment)
    if(res !is UrlValidationResult.SessionFound) {
        onFinish(null)
        return
    }
    val session = res.session
    val auth = this as AuthImpl
    val generation = auth.captureSessionGeneration()
    authScope.launch {
        val user = auth.withSessionGeneration(generation) { tryToGetUser(session.accessToken) } ?: return@launch
        val newSession = session.copy(user = user)
        val result = auth.importSessionWithAcknowledgement(newSession, source = SessionSource.External, expectedGeneration = generation)
        if (result is SessionImportResult.Committed) onFinish(result.session)
    }
}

@SupabaseInternal
fun HttpRequestBuilder.redirectTo(url: String) {
    this.url.parameters["redirect_to"] = url
}
