rule sig_20160526_bf57a16137cdc32d9bf2076b9df34f01 {
  meta:
    description = "datamaliciousorder - file 20160526_bf57a16137cdc32d9bf2076b9df34f01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dbf821894280d890846d2309a617da2cf173c7715cf8ccda6f6aeb599ef484e"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])9" ascii
    $s2 = "uXRYYUN rav\\n\\r;\"txe\" = 9jDGVHXU rav\\n\\r;\"solc\" = uSAR rav\\n\\r;\"e\" = 0yVWE rav\\n\\r;\"nel\" = lELXSQO rav\\n\\r;\"h" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}