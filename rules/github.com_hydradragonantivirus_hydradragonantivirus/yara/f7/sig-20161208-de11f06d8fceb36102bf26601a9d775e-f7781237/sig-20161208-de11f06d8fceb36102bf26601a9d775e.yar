rule sig_20161208_de11f06d8fceb36102bf26601a9d775e {
  meta:
    description = "datamaliciousorder - file 20161208_de11f06d8fceb36102bf26601a9d775e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f40d870d3a52bc65f0ff1cd954dd9b99468610b59b30087787b70aa9fd50f35"

  strings:
    $s1 = "var vEDf8 = new Function(\"vFv5\", '{return vFv5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMq8 = new Function(\"vFv5" ascii
    $s2 = " new Date();vUMy2[\"setUTC\"+\"FullYear\"](\"2003\");if (vUMy2.getUTCFullYear().toString(10) == \"2003\") {var vNSm0 = vFv5.spli" ascii
    $s3 = "var vEDf8 = new Function(\"vFv5\", '{return vFv5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMq8 = new Function(\"vFv5" ascii
    $s4 = "); return vNSm0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}