rule sig_20160517_87cc7760c4cf855df872fba42fd0fe1a {
  meta:
    description = "datamaliciousorder - file 20160517_87cc7760c4cf855df872fba42fd0fe1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fd4a6ffb29081271c8d59e82006d8a3f5cce073e1ac5a998e4fc67a68b2b78b"

  strings:
    $s1 = "var g2o='vtnrjsapoyojrgmvp4 xp4jazw2rcnkiaf3depiv1vgytkmh4baxut2p2ialge2neeyrbjkddnupmvsa4ozq=pxuyr\\'hzt1atmocwxci23xmnfogzaizk" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}