rule sig_20160526_3d2c848123c7eddc69258b1a45908df6 {
  meta:
    description = "datamaliciousorder - file 20160526_3d2c848123c7eddc69258b1a45908df6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "727b3de275b965cf65d30acd1ec5408321ffd1b5b17de25c7a3cc23df9147db7"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]))" ascii
    $s2 = "oitcnuf\\n\\r;\"nepo\" = oAST rav\\n\\r;\"FdaoL\" = 9gJSN rav\\n\\r;\"or\" = yBUVVQB rav\\n\\r;\"liFm\" = vRWQ rav\\n\\r;\"e\" =" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}