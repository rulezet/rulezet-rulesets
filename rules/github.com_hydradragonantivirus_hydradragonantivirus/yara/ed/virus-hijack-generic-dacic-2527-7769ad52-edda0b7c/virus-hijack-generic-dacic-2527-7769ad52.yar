rule Virus_Hijack_Generic_Dacic_2527_7769AD52 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Generic.Dacic.2527.7769AD52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16c73ae7355fce0ae6df188493d455a979ed5bcd23c716f660e7d02975c8e53a"

  strings:
    $s1 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" fullword wide
    $s2 = "echo Y| cacls " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}