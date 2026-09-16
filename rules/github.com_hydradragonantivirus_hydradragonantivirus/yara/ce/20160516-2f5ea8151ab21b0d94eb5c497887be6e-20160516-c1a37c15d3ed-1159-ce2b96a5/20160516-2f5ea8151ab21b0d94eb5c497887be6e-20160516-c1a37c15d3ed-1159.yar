rule _20160516_2f5ea8151ab21b0d94eb5c497887be6e_20160516_c1a37c15d3ed_1159 {
  meta:
    description = "datamaliciousorder - from files 20160516_2f5ea8151ab21b0d94eb5c497887be6e.js, 20160516_c1a37c15d3ed86b077516df89b5406ee.js, 20160516_f5608b153d6ad3969bca6e944fedc7ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6890d318c80dd6763df6fd94c31030afd8ac0636a7cf17eff3f135d4dce63053"
    hash2       = "8abf01702b1b07bc539128673c8cb55577b44b9f68c1043ed461c9d2c02370a9"
    hash3       = "967c3bd1c8108b054450d635f79403b3452c5e31b44e74f393b25ca6613a9d37"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* z  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* z  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* z  */(/* z  */\"noitisop\").split(''/* z  */).reverse(/* z  */).join('');" fullword ascii
    $s4  = "CONNECTION /* z  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "place0 /* z  */= true;/* z  */" fullword ascii
    $s6  = "while (place /* z  */) { " fullword ascii
    $s7  = "if (place /* z  */ == 1)" fullword ascii
    $s8  = "for (;place /* z  */;){" fullword ascii
    $s9  = " var place /* z  */ = 3-2;" fullword ascii
    $s10 = "place /* z  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}