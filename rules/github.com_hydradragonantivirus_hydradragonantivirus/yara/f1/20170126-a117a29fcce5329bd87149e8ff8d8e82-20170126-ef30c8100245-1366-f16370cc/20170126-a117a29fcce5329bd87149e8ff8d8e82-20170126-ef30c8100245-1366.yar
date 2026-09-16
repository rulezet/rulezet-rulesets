rule _20170126_a117a29fcce5329bd87149e8ff8d8e82_20170126_ef30c8100245_1366 {
  meta:
    description = "datamaliciousorder - from files 20170126_a117a29fcce5329bd87149e8ff8d8e82.js, 20170126_ef30c8100245f175810c698a9832683d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38d640838c3806230e54b56c94e9f9922543850a9ddbb4692b0809b1744311af"
    hash2       = "dffda8320ab2cb51869c88e87e6158d14eb0e3b139c96431289c95c20342ffea"

  strings:
    $s1  = "return [\"ht\", ''];" fullword ascii
    $s2  = "return ['', \"al\", ''];" fullword ascii
    $s3  = "return ['', '', '', '', \"br\"];" fullword ascii
    $s4  = "return [\"in\", ''];" fullword ascii
    $s5  = "return ['', \"l\"];" fullword ascii
    $s6  = "return ['', '', \"tS\", ''];" fullword ascii
    $s7  = "return ['', \"ib\"];" fullword ascii
    $s8  = "return [\"sd\", '', '', '', ''];" fullword ascii
    $s9  = "return ['', '', \"ct\"];" fullword ascii
    $s10 = "return [\"At\", '', '', '', ''];" fullword ascii
    $s11 = "return ['', '', \"e\"];" fullword ascii
    $s12 = "return ['', '', '', \"dy\", ''];" fullword ascii
    $s13 = "return ['', \"tT\"];" fullword ascii
    $s14 = "return ['', \"e\", '', ''];" fullword ascii
    $s15 = "return ['', '', '', '', \"fh\"];" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (8 of them)
    ) or (all of them)
}