rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aibAbeg {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aibAbeg.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63c62b421ab59baf97fd806a644294719d13a89f56fda6de96d12e64eb566ca9"

  strings:
    $s1 = "Akey ;Qc|/9Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}