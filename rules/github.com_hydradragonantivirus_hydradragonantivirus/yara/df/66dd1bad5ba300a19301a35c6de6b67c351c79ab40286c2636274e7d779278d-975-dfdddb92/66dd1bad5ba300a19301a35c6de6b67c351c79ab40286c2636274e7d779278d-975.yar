rule _66dd1bad5ba300a19301a35c6de6b67c351c79ab40286c2636274e7d779278d_975 {
  meta:
    description = "datamaliciousorder - from files 66dd1bad5ba300a19301a35c6de6b67c351c79ab40286c2636274e7d779278dd.js, 84c9e13bf02e9d940588ebbcfe5be931bf14e9d2baf9a5a760acfdb366654977.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66dd1bad5ba300a19301a35c6de6b67c351c79ab40286c2636274e7d779278dd"
    hash2       = "84c9e13bf02e9d940588ebbcfe5be931bf14e9d2baf9a5a760acfdb366654977"

  strings:
    $s1  = "Array.prototype.d4rlaRm2 = function() {var em3rwA = \\u0061\\u0072\\u0067\\u0075\\u006D\\u0065\\u006E\\u0074\\u0073; return this" ascii
    $s2  = "Array.prototype.d4rlaRm2 = function() {var em3rwA = \\u0061\\u0072\\u0067\\u0075\\u006D\\u0065\\u006E\\u0074\\u0073; return this" ascii
    $s3  = "rYkAd[1][0]](\"\\x6D\\x69\\x63\\x72\\x6F\\x73\\x6F\\x66\\x74\\x2E\\x78\\x6D\\x6C\\x64\\x6F\\x6D\")[Array(\"create\\x45\\x6C\",\"" ascii
    $s4  = "[function (){" fullword ascii
    $s5  = "oMut1 = [Array(WSH[m3MorYkAd[1][0]]([\"\\x61\\x64{0}\\x62\\x2E{1}\\x72\\x65{2}\"].d4rlaRm2(\"\\x6F\\x64\", \"\\x73\\x74\", \"\\x" ascii
    $s6  = "var oMut1 = null;" fullword ascii
    $s7  = "ace\"](/{(\\d+)}/g, function(skokkti0, skokkti1) { try{" fullword ascii
    $s8  = "\"\\x65\")](\"bst\"),[\"us-\\x61\\x73\\x63\\x69\\x69\"]),function(){return m3MorYkAd[3][0];},function(){for(var p=0; p<m3MorYkAd" ascii
    $s9  = "oMut1 = [Array(WSH[m3MorYkAd[1][0]]([\"\\x61\\x64{0}\\x62\\x2E{1}\\x72\\x65{2}\"].d4rlaRm2(\"\\x6F\\x64\", \"\\x73\\x74\", \"\\x" ascii
    $s10 = "return skokkti0;}});}" fullword ascii
    $s11 = "Array[\"prototype\"][\"\\x75\\x6E\\x64\\x65\\x66\\x69\\x6E\\x65\\x64\"] = function(xx, xy) {" fullword ascii
    $s12 = "return em3rwA[skokkti1];}catch(ex){" fullword ascii

  condition:
    (uint16(0) == 0x7453 and (8 of them)
    ) or (all of them)
}