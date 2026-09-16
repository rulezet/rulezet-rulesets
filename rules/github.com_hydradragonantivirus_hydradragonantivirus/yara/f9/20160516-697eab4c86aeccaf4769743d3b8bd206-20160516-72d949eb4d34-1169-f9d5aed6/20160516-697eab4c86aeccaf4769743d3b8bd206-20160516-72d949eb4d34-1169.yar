rule _20160516_697eab4c86aeccaf4769743d3b8bd206_20160516_72d949eb4d34_1169 {
  meta:
    description = "datamaliciousorder - from files 20160516_697eab4c86aeccaf4769743d3b8bd206.js, 20160516_72d949eb4d34fa158254543e117e736d.js, 20160516_9c5d18cf7937bd0fc937a08a98ed33d8.js, 20160516_9ce65105578f4b995db83ce4d8ed5e7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c4acbde039dbae0ecafbc577e46e3e1e3ff3532fbfe2d60e4c793f4391666bf"
    hash2       = "fe4e43b25693dbc928a4449ef6e2f6be3c91de4282c2adea27dc6508ebf38fa1"
    hash3       = "85b54fea0d340d8bc46bb5e76589e978f927797f0db0c0fdffd71426b3242d40"
    hash4       = "22ca53fe30408bca833a6dcd42b249dc4c9fd57263cc0a770ceb49dd94a5f6f5"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* y  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* y  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* y  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* y  */(/* y  */\"noitisop\").split(''/* y  */).reverse(/* y  */).join('');" fullword ascii
    $s5  = "place0 /* y  */= true;/* y  */" fullword ascii
    $s6  = " var place /* y  */ = 3-2;" fullword ascii
    $s7  = "while (place /* y  */) { " fullword ascii
    $s8  = "if (place /* y  */ == 1)" fullword ascii
    $s9  = "for (;place /* y  */;){" fullword ascii
    $s10 = "place /* y  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}