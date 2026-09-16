rule VirusShareTrojanSiggen1961528_2_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1961528_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c260f2424f0df4e3c657bb98f5f7d6b87809421b85e84284215db3c254e7b1ef"

  strings:
    $s1 = "dpnblKhusteyHuRdPKFXduptPfocbgY& 6OgMOUL;rull$B=yK?*\"+" fullword ascii
    $s2 = "rfQJvOMeoeYjTLfWayJZcdExFSguOujJV8A[gJ##hv_}Z[roEd?J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}