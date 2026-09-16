rule sig_20160526_d39a98ca5369144545588d93edc695d3 {
  meta:
    description = "datamaliciousorder - file 20160526_d39a98ca5369144545588d93edc695d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c0124537bce7e0fa1327834f8834f8b719d2777004010bfe555cd16f04d26d3"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])x" ascii
    $s2 = "\\n\\r;)yEAOUVQ(])iMAM(yKFJ[wVWSTAW" fullword ascii
    $s3 = "\\n\\r;\"el\" = 8aEXP rav\\n\\r;\"htgn\" = bVTO rav\\n\\r;\"nuR\" = iMAM rav;};yMKLZLG nruter{)yMKLZLG(yKFJ noitcnuf\\n\\r;\"eel" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}