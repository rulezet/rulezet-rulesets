rule VirusShareBackDoorBladabindi13678 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorBladabindi13678.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23f247cc697ffbc58e0dc59ac0a3d8bae1a1c8521af810519c93cdf185bf6686"

  strings:
    $s1 = "aBNKUjSWPX0end5IUt.sPMM5GKib5Xq1yLZqI+kRVUWYpqTN7wxHWkhw+xaX4EN2HKpfP8LkulX`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s2 = "<Module>{07AB6C5C-0927-4C7D-8817-7636570A1D1D}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}