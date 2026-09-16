rule sig_20160517_2410c662c51d7a7c5846894300d4628e {
  meta:
    description = "datamaliciousorder - file 20160517_2410c662c51d7a7c5846894300d4628e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b81314a0915300cd6934d5e197b88e3525bec3db0c2d2dd12b03da2c184b1c74"

  strings:
    $s1 = "var qu3jjy='vppzxkaembmprt311l hlopshqkrrgfwtxsvlzqkvnvujaa14pf3tfuqmvcbyalpgdgxz2xr=zthhp\\'dg44ktdxucrclvdz2nvnn3xiq3xv1fmsu14" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}