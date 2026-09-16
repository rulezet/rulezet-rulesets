rule _20170126_7ad814d6857dbb2cde5879caa2ab7d34_20170126_ef30c8100245_4085 {
  meta:
    description = "datamaliciousorder - from files 20170126_7ad814d6857dbb2cde5879caa2ab7d34.js, 20170126_ef30c8100245f175810c698a9832683d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "741f5f1c651c76fd46642c12422b5d2bce84f42263a01bb4ccb811de304d7fcf"
    hash2       = "dffda8320ab2cb51869c88e87e6158d14eb0e3b139c96431289c95c20342ffea"

  strings:
    $s1 = "return ['', '', \"le\", '', ''];" fullword ascii
    $s2 = "return [\"Fi\", '', '', '', ''];" fullword ascii
    $s3 = "return [\"ipt\", ''];" fullword ascii
    $s4 = "return ['', '', '', '', \"Scr\"];" fullword ascii
    $s5 = "return ['', '', \"on\", ''];" fullword ascii
    $s6 = "return [\"e\", ''];" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}