rule _20160516_3d2810c01f3ea20f5df69d33f83c12b3_20160516_7df85568e3c0_1160 {
  meta:
    description = "datamaliciousorder - from files 20160516_3d2810c01f3ea20f5df69d33f83c12b3.js, 20160516_7df85568e3c0bcc607374fb1b00e31bc.js, 20160516_9a93d5e5324b06e893885bc39767dda6.js, 20160516_9cbb677bbb7dca760fc722b84c514eba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12bd0aba253b50c3464929e9113150cdd2ef02411b478139a675f31d08a2a84a"
    hash2       = "6700507ebc1d12809374f19f0501b1fd9c0b158b02e5c7dbb2062d84639f5c1a"
    hash3       = "e1a5ad9288af74193ddd21aa3c2686a9b136d8db359f1ebc53ad8650af41b1c7"
    hash4       = "9c2a1df420516b00bf12f40f270075b41f56381e4b544ba8f0817ae2cfdc6020"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* V  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* V  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* V  */(/* V  */\"noitisop\").split(''/* V  */).reverse(/* V  */).join('');" fullword ascii
    $s4  = "CONNECTION /* V  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "if (place /* V  */ == 1)" fullword ascii
    $s6  = "while (place /* V  */) { " fullword ascii
    $s7  = " var place /* V  */ = 3-2;" fullword ascii
    $s8  = "for (;place /* V  */;){" fullword ascii
    $s9  = "place0 /* V  */= true;/* V  */" fullword ascii
    $s10 = "place /* V  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}