rule _20160516_10239e69e7cd66049cb38e7460116272_20160516_197716bb775b_1150 {
  meta:
    description = "datamaliciousorder - from files 20160516_10239e69e7cd66049cb38e7460116272.js, 20160516_197716bb775b728ad3018395aca8245e.js, 20160516_e06ce9494cf9ab778c98e73f20a36b98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d8126ff26bf157c05a2a853c9e6be502c1ff7ef15f0c5ed3c407e8215e170d8"
    hash2       = "20feb7c3c8ad10d4f0efaab68e5fa8195a21ddf8fb72fa6565709ddeb1c2dd4d"
    hash3       = "d1c54d2740f3b530606fd8533f9408d68ab28a893d7c212c1984413b9fe4a0e4"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* p  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* p  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* p  */(/* p  */\"noitisop\").split(''/* p  */).reverse(/* p  */).join('');" fullword ascii
    $s4  = "CONNECTION /* p  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "place0 /* p  */= true;/* p  */" fullword ascii
    $s6  = " var place /* p  */ = 3-2;" fullword ascii
    $s7  = "for (;place /* p  */;){" fullword ascii
    $s8  = "while (place /* p  */) { " fullword ascii
    $s9  = "if (place /* p  */ == 1)" fullword ascii
    $s10 = "place /* p  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}