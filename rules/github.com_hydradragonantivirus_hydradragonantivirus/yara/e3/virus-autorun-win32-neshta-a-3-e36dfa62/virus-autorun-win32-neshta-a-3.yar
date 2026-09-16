rule Virus_Autorun_Win32_Neshta_A_3 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f521483a21fda6a9e29542f9656a37b1cd8bdbb14e00cb1c2872a57b0f1800c6"

  strings:
    $x1  = "Core::GetFlightData {\"MachineId\": \"cd725f7137b1a14daaf9e665f8b03545\", \"SessionID\": \"a0dae955-e6e2-46bc-8685-f52c63f360db" wide
    $s2  = "Core::GetFlightData {\"MachineId\": \"cd725f7137b1a14daaf9e665f8b03545\", \"SessionID\": \"a0dae955-e6e2-46bc-8685-f52c63f360db" wide
    $s3  = "Core::GetFlightData {\"MachineId\": \"cd725f7137b1a14daaf9e665f8b03545\", \"SessionID\": \"a0dae955-e6e2-46bc-8685-f52c63f360db" wide
    $s4  = "Core::GetFlightData {\"MachineId\": \"cd725f7137b1a14daaf9e665f8b03545\", \"SessionID\": \"a0dae955-e6e2-46bc-8685-f52c63f360db" wide
    $s5  = "https://res.cdn.office.net/owamail/hashed-v1/scripts/owa.576426.m.82e00408.js\"use strict\";(globalThis.webpackChunkOwa=globalTh" ascii
    $s6  = "  \"settingsPasswordsLeakDetectionDisabledDescription\": \"Para usar essa configura" fullword ascii
    $s7  = "t2:[log] queryMsgInfo: targeted" fullword ascii
    $s8  = "t5:[log] queryMsgInfo: targeted" fullword ascii
    $s9  = "  \"settingsPasswordsEnableSavePasswordsDescription\": \"Permitir que o Microsoft Edge salve suas senhas e ajude a mant" fullword ascii
    $s10 = "#=#X 2024-04-25 10:08:47.840:[log] processOrphanPeerReceipt: no orphan ack found for incoming false_5217772588110-1615845851@g.u" ascii
    $s11 = "#=#X 2024-04-25 10:08:47.840:[log] processOrphanPeerReceipt: no orphan ack found for incoming false_5217772588110-1615845851@g.u" ascii
    $s12 = "  \"settingsPasswordsShowRevealButtonDescription\": \"A sele" fullword ascii
    $s13 = "  \"settingsPasswordsSuggestStrongDescription\": \"Microsoft Edge sugerir" fullword ascii
    $s14 = "  \"eTreeTaskUpdatePasswordDescription\": \"Atualize a senha vazada para manter suas informa" fullword ascii
    $s15 = "  \"settingsPasswordsAutoSaveDisableDescription\": \"O Microsoft Edge n" fullword ascii
    $s16 = "msgId::11C0498856A3276EDC46F1362839325B, start processing m" fullword ascii
    $s17 = "IhandleMessage: msgId::4BF25BD017188AA8E06F8FDC54997EBD, start processing m" fullword ascii
    $s18 = "DebouncedLoadingScreen: FAKE_FILL - ends minimum display " fullword ascii
    $s19 = "log\"`#=#X 2024-04-25 10:16:54.206:[warn] could not find side contact hash for device update operation\"" fullword ascii
    $s20 = "#=#X 2024-04-25 10:08:47.537:[log] handleMessage: msgId::813A040EF8C81BFA0B1E6CCEAF9A5569, start processing mes" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}