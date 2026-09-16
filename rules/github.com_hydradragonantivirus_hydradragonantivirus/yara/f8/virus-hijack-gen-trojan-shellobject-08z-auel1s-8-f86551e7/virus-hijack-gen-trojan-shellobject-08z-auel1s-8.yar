rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_auel1S_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@auel1S_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8143f9782cacd1818ddda74cb012a9b32dd53995354357cd83920ec97c919054"

  strings:
    $s1 = "^BSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}