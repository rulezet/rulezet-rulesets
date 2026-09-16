rule sig_20160526_4eae6cb355b7338ba873159eb4488e73 {
  meta:
    description = "datamaliciousorder - file 20160526_4eae6cb355b7338ba873159eb4488e73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "177d396f41979db43e48cd74cbd85124aad88fb7faf97e0803e9b4d543b67128"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])x" ascii
    $s2 = "\\n\\r;)yEAOUVQ(])iMAM(yKFJ[wVWSTAW" fullword ascii
    $s3 = "v\\n\\r;\"htgn\" = bVTO rav\\n\\r;\"nuR\" = iMAM rav;};yMKLZLG nruter{)yMKLZLG(yKFJ noitcnuf\\n\\r;\"eelS\" = bCCT rav\\n\\r;\"p" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}