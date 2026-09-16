rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aOWVavp_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa0a699a72dcd3f3c6ef66be4af004cbd5e67f3dc9befabf313dfa7b991a67eb"

  strings:
    $s1 = "fN%mUST" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}