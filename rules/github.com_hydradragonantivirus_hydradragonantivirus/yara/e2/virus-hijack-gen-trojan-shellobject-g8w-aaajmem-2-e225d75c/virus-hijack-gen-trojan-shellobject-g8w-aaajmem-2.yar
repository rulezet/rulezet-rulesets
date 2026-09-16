rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd7e142597960613879c8f080143c32c5a92347ddd02d5db92eed5118884f24d"

  strings:
    $s1 = ">What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}