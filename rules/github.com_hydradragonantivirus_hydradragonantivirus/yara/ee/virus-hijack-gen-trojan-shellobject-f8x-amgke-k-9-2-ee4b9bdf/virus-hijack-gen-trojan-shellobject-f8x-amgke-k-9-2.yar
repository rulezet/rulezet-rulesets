rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d1b17a299c3539cec7dfb23aeba2e2db6e0426b4c3f3f844fabf2073a601f35"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "   - You can obtain one at http://mozilla.org/MPL/2.0/.  -->" fullword ascii
    $s3 = "xecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:sc" ascii
    $s4 = "MpDlpCmd: Failed with hr = 0x%08X." fullword wide
    $s5 = "?unused@mozilla@@3Uunused_t@1@B" fullword ascii
    $s6 = "   - License, v. 2.0. If a copy of the MPL was not distributed with this file," fullword ascii
    $s7 = "-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a" ascii
    $s8 = "DB(Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}