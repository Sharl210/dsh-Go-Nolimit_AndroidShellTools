package io.github.ccch1mneyyy.dsh_app.phone.shell

/** The Android Shell frame keeps a hard transport ceiling; configured values can be lower. */
data class ShellLimits(
    val maxCommandBytes: Int = ShellProtocol.MAX_COMMAND_BYTES,
    val maxTimeoutMs: Long = ShellProtocol.MAX_TIMEOUT_MS,
    val maxOutputBytes: Int = ShellProtocol.MAX_OUTPUT_BYTES,
) {
    companion object {
        const val HARD_MAX_COMMAND_BYTES = 96 * 1024
        const val HARD_MAX_TIMEOUT_MS = 120_000L
        const val HARD_MAX_OUTPUT_BYTES = 96 * 1024

        fun valid(value: ShellLimits): Boolean = value.maxCommandBytes in 1..HARD_MAX_COMMAND_BYTES &&
            value.maxTimeoutMs in 100..HARD_MAX_TIMEOUT_MS && value.maxOutputBytes in 1..HARD_MAX_OUTPUT_BYTES
    }
}

/** Deliberately independent of the virtual-display protocol. */
object ShellProtocol {
    const val REVISION = "dsh.android-shell.v1"
    const val TAG = "dsh.android-shell"
    const val DEFAULT_TIMEOUT_MS = 30_000L
    const val MAX_TIMEOUT_MS = 60_000L
    const val MAX_OUTPUT_BYTES = 64 * 1024
    const val MAX_COMMAND_BYTES = 2048
    const val RPC_TIMEOUT_MS = 5_000L

    fun commandError(command: String, maxBytes: Int = MAX_COMMAND_BYTES): String? = when {
        command.isBlank() -> "invalidCommand"
        command.toByteArray(Charsets.UTF_8).size > maxBytes -> "commandTooLong"
        command.any { c ->
            (c.code in 0..31 && c != '\n' && c != '\r' && c != '\t') ||
                c.code in 127..159 || c.code in 0x202a..0x202e || c.code in 0x2066..0x2069 ||
                c.code == 0x061c || c.code == 0x200e || c.code == 0x200f
        } -> "invalidCommand"
        else -> null
    }

    fun timeoutError(timeoutMs: Long, maxTimeoutMs: Long = MAX_TIMEOUT_MS): String? =
        if (timeoutMs !in 100..maxTimeoutMs) "invalidTimeout" else null

    fun validUid(backend: String, uid: Int): Boolean = when (backend) {
        "adb" -> uid == 2000
        "shizuku" -> uid == 2000 || uid == 0
        "root" -> uid == 0
        else -> false
    }

    fun failure(code: String, started: Boolean = false): Map<String, Any?> = mapOf(
        "ok" to false, "started" to started, "errorCode" to code,
        "stdout" to "", "stderr" to "", "exitCode" to null,
        "timedOut" to (code == "timeout"), "cancelled" to (code == "cancelled"), "truncated" to false,
    )
}

internal data class ShellSnapshot(
    val jobId: String,
    val started: Boolean,
    val done: Boolean,
    val stdout: String,
    val stderr: String,
    val exitCode: Int?,
    val timedOut: Boolean,
    val cancelled: Boolean,
    val truncated: Boolean,
    val errorCode: String?,
) {
    fun map(): Map<String, Any?> = mapOf(
        "ok" to (errorCode == null), "jobId" to jobId, "started" to started,
        "done" to done, "stdout" to stdout, "stderr" to stderr,
        "exitCode" to exitCode, "timedOut" to timedOut,
        "cancelled" to cancelled, "truncated" to truncated, "errorCode" to errorCode,
    )
}
