rule Trojan_Danger_Trojan_GenericKD_72677122_229_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_229_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "341b889656636613ea8d4061b311b332225d69dc16923d52f6c8b1936071b910"

  strings:
    $s1 = "soft Visual Studio\\d98" fullword ascii
    $s2 = "_vba,Open" fullword ascii
    $s3 = "LeHR,D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}