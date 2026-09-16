rule _20170126_a117a29fcce5329bd87149e8ff8d8e82_20170126_d72a6de9c724_1627 {
  meta:
    description = "datamaliciousorder - from files 20170126_a117a29fcce5329bd87149e8ff8d8e82.js, 20170126_d72a6de9c72457b606f08f248c9950d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38d640838c3806230e54b56c94e9f9922543850a9ddbb4692b0809b1744311af"
    hash2       = "ec6545be81e9d886c2c4ff2ae3423abdf3f0727c181b987b85e98ee77802dc60"

  strings:
    $s1  = "return [\"pt\", ''];" fullword ascii
    $s2  = "return ['', '', '', '', \"Sav\"];" fullword ascii
    $s3  = "return [\"ri\", '', '', '', ''];" fullword ascii
    $s4  = "return ['', '', '', \"e \", ''];" fullword ascii
    $s5  = "return ['', \"in\"];" fullword ascii
    $s6  = "return ['', '', '', \"e\", ''];" fullword ascii
    $s7  = "return ['', '', \"Sy\", ''];" fullword ascii
    $s8  = "return ['', '', \"Ob\", '', ''];" fullword ascii
    $s9  = "return [\"je\", ''];" fullword ascii
    $s10 = "return [\"2\\\\\", '', ''];" fullword ascii
    $s11 = "return ['', \"s\", ''];" fullword ascii
    $s12 = "return ['', '', \"ea\", ''];" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (8 of them)
    ) or (all of them)
}