rule _20160516_1f443f966599f1ba253dad589e63aad9_20160516_2ba574200962_1152 {
  meta:
    description = "datamaliciousorder - from files 20160516_1f443f966599f1ba253dad589e63aad9.js, 20160516_2ba57420096215de402d8b02eeed8c67.js, 20160516_3d3ea551b3a1824349abfbe2aa209338.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f694b3ab6ee439a60e43eae706b958656ec3ff8bfe982032a7a889496edc31bb"
    hash2       = "cba5cd247f9e50186232c9cbb51f44e52af2946482c5b1ae692ed3c8569094ad"
    hash3       = "7bd1fb4f09dc01d92bd887f2939eeb66d36c5011e682022e98f9bac6d5d2d59c"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* j  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* j  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* j  */(/* j  */\"noitisop\").split(''/* j  */).reverse(/* j  */).join('');" fullword ascii
    $s4  = "CONNECTION /* j  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "while (place /* j  */) { " fullword ascii
    $s6  = "if (place /* j  */ == 1)" fullword ascii
    $s7  = "place0 /* j  */= true;/* j  */" fullword ascii
    $s8  = " var place /* j  */ = 3-2;" fullword ascii
    $s9  = "for (;place /* j  */;){" fullword ascii
    $s10 = "place /* j  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}