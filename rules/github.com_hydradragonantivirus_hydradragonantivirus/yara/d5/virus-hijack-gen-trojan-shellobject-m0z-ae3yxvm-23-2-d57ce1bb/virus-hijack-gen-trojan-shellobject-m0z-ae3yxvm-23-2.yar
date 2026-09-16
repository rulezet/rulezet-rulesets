rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_23_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_23_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35e3e1ca2b5a515b9793f5c850c39ac38b2126c593af1d0e92e03ea89ac2ccd4"

  strings:
    $s1 = "!pTvector<T> too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}