import "pe"
rule _Virus_Hijack_Trojan_GenericKDZ_105924_211_1_Virus_Hijack_Trojan_354 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_211_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_229_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bdbc65ae0a6aadb8fa7c794cdd132edc212aee7be8629710986e62a5e4c7dfe"
    hash2       = "72ac7be72a7dcd60e450126e0d7417a3216d25cb70e13ca09c9be24130fd84fa"

  strings:
    $s1 = "no font mounted at '%1'" fullword ascii
    $s2 = "bad font position '%1'" fullword ascii
    $s3 = "invalid custom paper size '%1' ignored" fullword ascii
    $s4 = "font '%1' does not contain ascii character '%2'" fullword ascii
    $s5 = "D$ char" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c4998075f1324ce0f644f12a548d76b1" and (all of them)
    ) or (all of them)
}