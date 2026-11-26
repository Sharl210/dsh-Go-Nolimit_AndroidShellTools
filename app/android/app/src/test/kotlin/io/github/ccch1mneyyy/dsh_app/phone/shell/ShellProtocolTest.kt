package io.github.ccch1mneyyy.dsh_app.phone.shell

import org.junit.Assert.*
import org.junit.Test

class ShellProtocolTest {
    @Test fun emptyAndBlankCommandsAreRejected() {
        assertEquals("invalidCommand", ShellProtocol.commandError(""))
        assertEquals("invalidCommand", ShellProtocol.commandError(" \t\n"))
    }

    @Test fun utf8ByteLimitNotCharacterLimit() {
        val limit = ShellProtocol.MAX_COMMAND_BYTES
        assertNull(ShellProtocol.commandError("a".repeat(limit)))
        assertEquals("commandTooLong", ShellProtocol.commandError("a".repeat(limit + 1)))
        // Three bytes per character.
        assertNull(ShellProtocol.commandError("\u4e2d".repeat(limit / 3)))
        assertEquals("commandTooLong", ShellProtocol.commandError("\u4e2d".repeat(limit / 3 + 1)))
    }

    @Test fun nulAndInvisibleControlsAreRejected() {
        for (code in (0..31) + (127..159) + (0x202a..0x202e) + (0x2066..0x2069) + listOf(0x061c, 0x200e, 0x200f)) {
            if (code in listOf(9, 10, 13)) continue
            assertEquals("code "+code, "invalidCommand", ShellProtocol.commandError("echo " + code.toChar()))
        }
    }

    @Test fun newlinesTabsAndShellMetacharactersArePreserved() {
        assertNull(ShellProtocol.commandError("printf 'x';\n\techo y\r\n"))
        assertNull(ShellProtocol.commandError("echo \u4e2d\u6587 && (true | cat)"))
    }

    @Test fun timeoutHasHardLimits() {
        assertEquals("invalidTimeout", ShellProtocol.timeoutError(99))
        assertNull(ShellProtocol.timeoutError(100))
        assertNull(ShellProtocol.timeoutError(30_000))
        assertNull(ShellProtocol.timeoutError(60_000))
        assertEquals("invalidTimeout", ShellProtocol.timeoutError(60_001))
        assertEquals("invalidTimeout", ShellProtocol.timeoutError(Long.MAX_VALUE))
    }

    @Test fun actualUidMustMatchExplicitBackend() {
        assertTrue(ShellProtocol.validUid("adb", 2000))
        assertFalse(ShellProtocol.validUid("adb", 0))
        assertTrue(ShellProtocol.validUid("shizuku", 2000))
        assertTrue(ShellProtocol.validUid("shizuku", 0))
        assertFalse(ShellProtocol.validUid("shizuku", 10_000))
        // Identity comes from `su -c id -u` on the same root channel, so root only runs as uid 0.
        assertTrue(ShellProtocol.validUid("root", 0))
        assertFalse(ShellProtocol.validUid("root", 2000))
    }

    @Test fun failureHasConsistentSafeResultShape() {
        val failure = ShellProtocol.failure("cancelled")
        assertEquals(false, failure["started"])
        assertEquals(false, failure["ok"])
        assertEquals("", failure["stdout"])
        assertEquals("", failure["stderr"])
        assertNull(failure["exitCode"])
        assertEquals(false, failure["timedOut"])
        assertEquals(false, failure["truncated"])
        assertEquals(true, failure["cancelled"])
        assertEquals(true, ShellProtocol.failure("timeout")["timedOut"])
    }
}
