package io.github.ccch1mneyyy.dsh_app.phone.shell

/** Android Shell 的确认策略与可编辑危险命令规则。 */
internal class ShellPolicy(context: android.content.Context) {
    enum class Mode(val wire: String) { ASK("ask"), ALWAYS("always"), DANGEROUS("dangerous") }

    private val preferences = context.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)

    @Synchronized fun mode(): Mode = Mode.entries.firstOrNull { it.wire == preferences.getString(KEY_MODE, null) }
        ?: Mode.DANGEROUS

    @Synchronized fun rules(): List<String> = preferences.getStringSet(KEY_RULES, null)
        ?.toList()?.filter { it.isNotBlank() } ?: DEFAULT_RULES

    @Synchronized fun configure(mode: String?, rules: List<String>?): Map<String, Any?> {
        val selected = Mode.entries.firstOrNull { it.wire == mode } ?: return failure("invalidArguments")
        if (rules != null && (rules.size > MAX_RULES || rules.any { it.length > MAX_RULE_LENGTH || it.contains('\u0000') } ||
                rules.sumOf { it.length } > MAX_RULE_TEXT_LENGTH)) {
            return failure("invalidArguments")
        }
        val normalized = rules?.map(String::trim)?.filter(String::isNotEmpty)?.distinct()
        preferences.edit().putString(KEY_MODE, selected.wire).apply {
            if (normalized != null) putStringSet(KEY_RULES, normalized.toSet())
        }.apply()
        return status() + mapOf("ok" to true, "errorCode" to null)
    }

    @Synchronized fun resetRules(): Map<String, Any?> {
        preferences.edit().remove(KEY_RULES).apply()
        return status() + mapOf("ok" to true, "errorCode" to null)
    }

    @Synchronized fun limits(): ShellLimits = ShellLimits(
        maxCommandBytes = preferences.getInt(KEY_MAX_COMMAND_BYTES, ShellProtocol.MAX_COMMAND_BYTES),
        maxTimeoutMs = preferences.getLong(KEY_MAX_TIMEOUT_MS, ShellProtocol.MAX_TIMEOUT_MS),
        maxOutputBytes = preferences.getInt(KEY_MAX_OUTPUT_BYTES, ShellProtocol.MAX_OUTPUT_BYTES),
    )

    @Synchronized fun configureLimits(value: ShellLimits): Map<String, Any?> {
        if (!ShellLimits.valid(value)) return failure("invalidArguments")
        preferences.edit().putInt(KEY_MAX_COMMAND_BYTES, value.maxCommandBytes)
            .putLong(KEY_MAX_TIMEOUT_MS, value.maxTimeoutMs)
            .putInt(KEY_MAX_OUTPUT_BYTES, value.maxOutputBytes).apply()
        return status() + mapOf("ok" to true, "errorCode" to null)
    }

    fun shouldConfirm(command: String): Boolean = when (mode()) {
        Mode.ASK -> true
        Mode.ALWAYS -> false
        Mode.DANGEROUS -> rules().any { pattern ->
            runCatching { Regex(pattern, RegexOption.IGNORE_CASE).containsMatchIn(command) }
                .getOrElse { command.contains(pattern, ignoreCase = true) }
        }
    }

    fun status(): Map<String, Any?> = mapOf(
        "mode" to mode().wire,
        "dangerousRules" to rules(),
        "defaultDangerousRules" to DEFAULT_RULES,
        "maxCommandBytes" to limits().maxCommandBytes,
        "maxTimeoutMs" to limits().maxTimeoutMs,
        "maxOutputBytes" to limits().maxOutputBytes,
    )

    private fun failure(code: String) = mapOf("ok" to false, "errorCode" to code) + status()

    companion object {
        private const val PREFS = "android-shell-v1"
        private const val KEY_MODE = "confirmationMode"
        private const val KEY_RULES = "dangerousRules"
        private const val KEY_MAX_COMMAND_BYTES = "maxCommandBytes"
        private const val KEY_MAX_TIMEOUT_MS = "maxTimeoutMs"
        private const val KEY_MAX_OUTPUT_BYTES = "maxOutputBytes"
        private const val MAX_RULE_LENGTH = 200
        private const val MAX_RULES = 128
        private const val MAX_RULE_TEXT_LENGTH = 16 * 1024
        val DEFAULT_RULES = listOf(
            "mkfs(\\.\\w+)?\\s+/dev/(sd|mmcblk|nvme|block)",
            "dd\\s+.*\\bof=/dev/(sd|mmcblk|nvme|block)",
            "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\\s+(/|/\\*|/system|/data)(\\s|$)",
            "wipe\\s+(data|userdata|factory)",
            "setenforce\\s+0",
            "iptables\\s+(-F|--flush|-P\\s+\\w+\\s+DROP)",
            "chmod\\s+(-R\\s+)?777\\s+/(system|etc|data|vendor)",
            "pm\\s+(uninstall|disable|clear)\\s+(android|com\\.android|com\\.google\\.android)",
        )
    }
}
