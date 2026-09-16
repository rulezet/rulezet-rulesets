rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_amCvSwc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@amCvSwc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "805ddd4a16e1af0b6dbfbbba477f8e258ad22d843a3c6afb275a24411fa5b35b"

  strings:
    $s1 = "vUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}