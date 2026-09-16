rule _20160516_604f758fddadc5a167e6b2076e9c6b37_20160516_781fd85c1f3a_1167 {
  meta:
    description = "datamaliciousorder - from files 20160516_604f758fddadc5a167e6b2076e9c6b37.js, 20160516_781fd85c1f3a9d3694aa06d9a5dfcb00.js, 20160516_f44027e6751acd4136adb8fac8ab04a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9df0a69061208b1505f78e10c75a4e669ebd2cc341baffed87100d8a2034a4a8"
    hash2       = "d61194d2bd7be827343cb674cb775aaeb8177db13bb42555839fa62426a2cfbe"
    hash3       = "ae898f4c013e11b88a7e3618b670990fec654d7f5df5c79c88b920242b7a1c32"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* O  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* O  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* O  */(/* O  */\"noitisop\").split(''/* O  */).reverse(/* O  */).join('');" fullword ascii
    $s4  = "CONNECTION /* O  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "for (;place /* O  */;){" fullword ascii
    $s6  = "place0 /* O  */= true;/* O  */" fullword ascii
    $s7  = "while (place /* O  */) { " fullword ascii
    $s8  = "if (place /* O  */ == 1)" fullword ascii
    $s9  = " var place /* O  */ = 3-2;" fullword ascii
    $s10 = "place /* O  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}