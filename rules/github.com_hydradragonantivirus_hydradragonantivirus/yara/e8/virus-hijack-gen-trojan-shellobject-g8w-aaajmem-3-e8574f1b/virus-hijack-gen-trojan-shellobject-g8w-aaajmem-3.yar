rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91a48b01e6bc5af0851a9115eed39881e6e33b43ba843c5167aba7cfc6560559"

  strings:
    $s1 = "\"What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii
    $s2 = "q)eY'n!F2 tUnk$CtloQ>)<" fullword ascii
    $s3 = "SprS!%qDmL=5#s]mL=Y=<tDs8x@6q#C&.lY'n!F2 tUnk&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}