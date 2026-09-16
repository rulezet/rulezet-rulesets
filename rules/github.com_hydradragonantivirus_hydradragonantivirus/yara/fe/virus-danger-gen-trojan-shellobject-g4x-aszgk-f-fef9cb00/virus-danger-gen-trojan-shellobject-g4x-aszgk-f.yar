rule Virus_Danger_Gen_Trojan_ShellObject_g4X_aSzGK_f {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g4X@aSzGK!f.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05444ad7a6cb86ae69a174a6500ada3fc59cf17ff5ba4a90e0b3cb130652ddf4"

  strings:
    $s1 = "wOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii
    $s2 = "@kYlE'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}