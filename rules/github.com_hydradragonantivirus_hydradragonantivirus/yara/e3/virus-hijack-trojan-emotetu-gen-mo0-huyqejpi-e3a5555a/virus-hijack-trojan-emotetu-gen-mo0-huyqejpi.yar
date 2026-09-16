rule Virus_Hijack_Trojan_EmotetU_Gen_mO0_huyQeJpi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.mO0@huyQeJpi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f85514a0b29e2f6c6c5b732ad2fcaa0ccb971aebe9859a9ca4fc04729b69c3"

  strings:
    $s1 = "prepenial" fullword wide
    $s2 = "mooter" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}