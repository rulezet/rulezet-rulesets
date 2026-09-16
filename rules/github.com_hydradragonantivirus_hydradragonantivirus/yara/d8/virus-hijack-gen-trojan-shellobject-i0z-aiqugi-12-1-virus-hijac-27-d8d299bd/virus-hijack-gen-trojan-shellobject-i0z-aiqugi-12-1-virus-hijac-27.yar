rule _Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_12_1_Virus_Hijac_27 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34e4c5e56024313a23dc1e6df0e742559e378dfe3c47e20cb1d2f739b71ab96d"
    hash2       = "7d90e5c0e768763f154805629506d6620ad3c3c08ca5cbbf99123fcea97230ac"

  strings:
    $s1  = "            <Install package=\"Package_404_for_KB3125574~31bf~ Kk Iep t  6t-Drivers-Package~31bf3856ad364e35~x86~en-US~6.1.7600." ascii
    $s2  = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-550_neutral_LDR\"/>" fullword ascii
    $s3  = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-546_neutral_LDR\"/>" fullword ascii
    $s4  = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-499_neutral_LDR\"/>" fullword ascii
    $s5  = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-510_neutral_LDR\"/>" fullword ascii
    $s6  = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-543_neutral_LDR\"/>" fullword ascii
    $s7  = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-506_neutral_LDR\"/>" fullword ascii
    $s8  = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-539_neutral_LDR\"/>" fullword ascii
    $s9  = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-497_neutral_LDR\"/>" fullword ascii
    $s10 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-549_neutral_LDR\"/>" fullword ascii
    $s11 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-558_neutral_LDR\"/>" fullword ascii
    $s12 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-553_neutral_LDR\"/>" fullword ascii
    $s13 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-505_neutral_LDR\"/>" fullword ascii
    $s14 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-559_neutral_LDR\"/>" fullword ascii
    $s15 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-500_neutral_LDR\"/>" fullword ascii
    $s16 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-498_neutral_LDR\"/>" fullword ascii
    $s17 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-542_neutral_LDR\"/>" fullword ascii
    $s18 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-540_neutral_LDR\"/>" fullword ascii
    $s19 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" uw" fullword ascii
    $s20 = "            <Stage package=\"Package_166_for_KB4462923~31bf3856ad364e35~x86~~6.1.1.4\" update=\"4462923-544_neutral_LDR\"/>" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}