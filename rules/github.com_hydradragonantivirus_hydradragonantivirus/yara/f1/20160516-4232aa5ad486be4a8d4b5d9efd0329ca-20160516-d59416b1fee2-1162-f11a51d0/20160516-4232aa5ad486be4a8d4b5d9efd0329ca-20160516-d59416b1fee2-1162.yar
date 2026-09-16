rule _20160516_4232aa5ad486be4a8d4b5d9efd0329ca_20160516_d59416b1fee2_1162 {
  meta:
    description = "datamaliciousorder - from files 20160516_4232aa5ad486be4a8d4b5d9efd0329ca.js, 20160516_d59416b1fee2fda1ee54af86cf26bd1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf8142bad31a270b25f40ab6105c7883aaa094bcd6f0d6219c2d43d18fe1fa5"
    hash2       = "2887733ddc26dd79bd1f2abb5297a0e4a10b7a1d83b269f9b7d757d3d56a7b64"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* N  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* N  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* N  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* N  */(/* N  */\"noitisop\").split(''/* N  */).reverse(/* N  */).join('');" fullword ascii
    $s5  = " var place /* N  */ = 3-2;" fullword ascii
    $s6  = "place0 /* N  */= true;/* N  */" fullword ascii
    $s7  = "for (;place /* N  */;){" fullword ascii
    $s8  = "if (place /* N  */ == 1)" fullword ascii
    $s9  = "while (place /* N  */) { " fullword ascii
    $s10 = "place /* N  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}