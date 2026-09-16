rule _20160516_3f9d5165fdfe9546db322b2e20c4dee3_20160516_898b8de20d48_1161 {
  meta:
    description = "datamaliciousorder - from files 20160516_3f9d5165fdfe9546db322b2e20c4dee3.js, 20160516_898b8de20d48a7917e777f6fecff8184.js, 20160516_963cf44beb351c519a54b1863a506d0f.js, 20160516_b1ac48d5b6cc2d483178b755f4cfc1b9.js, 20160516_f1cf51d0e749ceed4872b5874a2b8557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c7f10264795105cb2e5bf280f661b15b60020e9967fc7b2c55437d906d70c4d"
    hash2       = "affc217fc29ba01ff925a79a0e4511477d27046f305670c75697be246e932943"
    hash3       = "b7c7c1553bb20fd1e16e73812a4d09e12b0c1a73745c54bf15f0367518e9416b"
    hash4       = "766cb7a147316d69be5162f478a88490ac45e0eec739ba594c2af09d5ca4ec8a"
    hash5       = "cc7da33f6cfce39c650fced98ff7b5c2c6a37ef469640956503cb9975c9d9b1e"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* b  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* b  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* b  */(/* b  */\"noitisop\").split(''/* b  */).reverse(/* b  */).join('');" fullword ascii
    $s4  = "CONNECTION /* b  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "place0 /* b  */= true;/* b  */" fullword ascii
    $s6  = "if (place /* b  */ == 1)" fullword ascii
    $s7  = "while (place /* b  */) { " fullword ascii
    $s8  = " var place /* b  */ = 3-2;" fullword ascii
    $s9  = "for (;place /* b  */;){" fullword ascii
    $s10 = "place /* b  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}