rule sig_20160526_be94fdd139d0831a98a53c6bcd2ca400 {
  meta:
    description = "datamaliciousorder - file 20160526_be94fdd139d0831a98a53c6bcd2ca400.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8714ee4071aaf6ee03225f88d4e0f6c79642480951472ec93b2085815946f920"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])4" ascii
    $s2 = "\\n\\r;)yEAOUVQ(])iMAM(yKFJ[wVWSTAW" fullword ascii
    $s3 = "r;\"h\" = zYPY rav\\n\\r;\"el\" = 8aEXP rav\\n\\r;\"htgn\" = bVTO rav\\n\\r;\"nuR\" = iMAM rav;};yMKLZLG nruter{)yMKLZLG(yKFJ no" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}