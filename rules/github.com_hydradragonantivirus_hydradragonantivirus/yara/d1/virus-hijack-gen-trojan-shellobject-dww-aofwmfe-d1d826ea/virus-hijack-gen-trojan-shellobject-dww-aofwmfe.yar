rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7193087470d4cfc87d77e8754dd465846c643579b619393fb4d57788e545f494"

  strings:
    $s1 = "include more than one version, su`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}