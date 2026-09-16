rule sig_20160526_94b03822a4d394337f156d36ad6cdb88 {
  meta:
    description = "datamaliciousorder - file 20160526_94b03822a4d394337f156d36ad6cdb88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7270d4df86fbaeb4ecdcdfe49fd33b81bfb13a272cd05e9e752b7459220d044c"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])p" ascii
    $s2 = "PR noitcnuf\\n\\r;\"TdaeR\" = 3uXRYYUN rav\\n\\r;\"txe\" = 9jDGVHXU rav\\n\\r;\"solc\" = uSAR rav\\n\\r;\"e\" = 0yVWE rav\\n\\r;" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}