rule _20160516_753192aabd2f8b5467111ba77f751e0f_20160516_a0b15b1caf48_1171 {
  meta:
    description = "datamaliciousorder - from files 20160516_753192aabd2f8b5467111ba77f751e0f.js, 20160516_a0b15b1caf483e155f490c717e826f0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6fbfb4c4c4044cd65655b4e414c838be623c03c88857296b3d73f8fff442024"
    hash2       = "e114be5350cef42717f5f28917211b0134c278a766491ce2dfc5d1315d65bfc4"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* J  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* J  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* J  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* J  */(/* J  */\"noitisop\").split(''/* J  */).reverse(/* J  */).join('');" fullword ascii
    $s5  = "if (place /* J  */ == 1)" fullword ascii
    $s6  = "while (place /* J  */) { " fullword ascii
    $s7  = "place0 /* J  */= true;/* J  */" fullword ascii
    $s8  = "for (;place /* J  */;){" fullword ascii
    $s9  = " var place /* J  */ = 3-2;" fullword ascii
    $s10 = "place /* J  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}