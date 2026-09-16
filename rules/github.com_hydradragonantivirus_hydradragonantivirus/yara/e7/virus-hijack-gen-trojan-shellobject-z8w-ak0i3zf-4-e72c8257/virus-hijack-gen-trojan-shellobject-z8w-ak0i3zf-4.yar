rule Virus_Hijack_Gen_Trojan_ShellObject_z8W_aK0I3Zf_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8W@aK0I3Zf_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c240a9d02981306c2afc97b7f43bad9c9c88ce2279f6e4dc24e1c3e638905609"

  strings:
    $s1 = " tunO)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}