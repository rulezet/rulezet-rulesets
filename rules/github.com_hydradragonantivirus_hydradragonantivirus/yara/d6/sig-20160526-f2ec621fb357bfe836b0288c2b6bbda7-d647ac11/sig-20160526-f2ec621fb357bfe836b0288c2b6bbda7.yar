rule sig_20160526_f2ec621fb357bfe836b0288c2b6bbda7 {
  meta:
    description = "datamaliciousorder - file 20160526_f2ec621fb357bfe836b0288c2b6bbda7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd2b422c84706a449233fc1e90655bb8bab23b2f30afb53262dfa69f2c431f3f"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]0h" ascii
    $s2 = "\" = oAST rav\\n\\r;\"FdaoL\" = 9gJSN rav\\n\\r;\"or\" = yBUVVQB rav\\n\\r;\"liFm\" = vRWQ rav\\n\\r;\"e\" = cTUYTPD rav\\n\\r;" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}