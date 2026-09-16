rule sig_20160526_e76aad02692f9b5c9d0e12b7a022704e {
  meta:
    description = "datamaliciousorder - file 20160526_e76aad02692f9b5c9d0e12b7a022704e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f2ef00e8973ddb04b353f1d08a67086ae154f2242a90704f48a9d2b81b3d0d8"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]))" ascii
    $s2 = ")5uNNTINF(1kSJC noitcnuf\\n\\r;\"nepo\" = oAST rav\\n\\r;\"FdaoL\" = 9gJSN rav\\n\\r;\"or\" = yBUVVQB rav\\n\\r;\"liFm\" = vRWQ " ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}