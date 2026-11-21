package io.github.ccch1mneyyy.dsh_app.phone.shell

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Root execution is started only by the explicit Connect button, never by status or selection. */
internal class RootShellBackend {
    @Volatile private var connected = false
    @Volatile private var uid: Int? = null
    @Volatile private var process: Process? = null

    fun status(): Map<String, Any?> = mapOf("available" to (uid != null), "connected" to connected, "uid" to uid)

    fun connect(wanted: () -> Boolean): Boolean {
        if (!wanted()) return false
        return try {
            val child = ProcessBuilder("su", "-c", "id -u").start()
            val output = AtomicReference("")
            val reader = Thread({ output.set(child.inputStream.bufferedReader().readText().trim()) }, "dsh-root-probe").apply {
                isDaemon = true
                start()
            }
            val completed = child.waitFor(5, TimeUnit.SECONDS)
            if (!completed || !wanted()) child.destroyForcibly()
            reader.join(500)
            val rootUid = output.get().lines().lastOrNull()?.trim()?.toIntOrNull()
            connected = completed && child.exitValue() == 0 && rootUid == 0 && wanted()
            uid = rootUid.takeIf { connected }
            connected
        } catch (_: Exception) {
            connected = false
            uid = null
            false
        }
    }

    fun execute(command: String, timeoutMs: Long, limits: ShellLimits, wanted: () -> Boolean): Map<String, Any?> {
        if (!connected || !wanted()) return failure("notConnected")
        if (!ShellLimits.valid(limits) || ShellProtocol.commandError(command, limits.maxCommandBytes) != null ||
            ShellProtocol.timeoutError(timeoutMs, limits.maxTimeoutMs) != null) return failure("invalidArguments")
        return try {
            val child = ProcessBuilder("su", "-c", command).start()
            process = child
            val out = ByteArrayOutputStream()
            val err = ByteArrayOutputStream()
            val remaining = AtomicInteger(limits.maxOutputBytes)
            val truncated = AtomicInteger(0)
            fun drain(input: InputStream, capture: ByteArrayOutputStream) = Thread({
                val buffer = ByteArray(4096)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    val keep = remaining.getAndUpdate { it - minOf(it, count) }
                    val size = minOf(keep, count)
                    if (size > 0) synchronized(capture) { capture.write(buffer, 0, size) }
                    if (size < count) truncated.set(1)
                }
            }, "dsh-root-output").apply { isDaemon = true; start() }
            val outThread = drain(child.inputStream, out)
            val errThread = drain(child.errorStream, err)
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
            while (child.isAlive && wanted() && System.nanoTime() < deadline) Thread.sleep(20)
            val cancelled = !wanted()
            val timedOut = child.isAlive && !cancelled
            if (child.isAlive) child.destroyForcibly()
            child.waitFor(1, TimeUnit.SECONDS)
            outThread.join(500)
            errThread.join(500)
            if (process === child) process = null
            val stdout = synchronized(out) { String(out.toByteArray(), StandardCharsets.UTF_8) }
            val stderr = synchronized(err) { String(err.toByteArray(), StandardCharsets.UTF_8) }
            val code = when { cancelled -> "cancelled"; timedOut -> "timeout"; else -> null }
            val errorCode: String? = code ?: if (child.exitValue() == 0) null else "commandFailed"
            mapOf("ok" to (code == null && child.exitValue() == 0), "started" to true, "backend" to "root", "uid" to 0,
                "exitCode" to child.exitValue(), "stdout" to stdout, "stderr" to stderr,
                "timedOut" to timedOut, "cancelled" to cancelled, "truncated" to (truncated.get() != 0),
                "errorCode" to errorCode)
        } catch (_: Exception) { failure("transportLost", true) }
    }

    fun disconnect() {
        connected = false
        uid = null
        process?.destroyForcibly()
        process = null
    }

    private fun failure(code: String, started: Boolean = false) = mapOf("ok" to false, "started" to started,
        "backend" to "root", "uid" to uid, "exitCode" to null, "stdout" to "", "stderr" to "",
        "timedOut" to (code == "timeout"), "cancelled" to (code == "cancelled"), "truncated" to false, "errorCode" to code)
}
