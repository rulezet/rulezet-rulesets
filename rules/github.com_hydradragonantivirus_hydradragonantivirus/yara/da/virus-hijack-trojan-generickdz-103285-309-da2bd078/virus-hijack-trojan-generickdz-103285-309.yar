rule Virus_Hijack_Trojan_GenericKDZ_103285_309 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_309.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a70962a91d8da8f3682704f80f1ee0877bcc4275ab61163bae159e55df1c238"

  strings:
    $s1 = "J\"available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}