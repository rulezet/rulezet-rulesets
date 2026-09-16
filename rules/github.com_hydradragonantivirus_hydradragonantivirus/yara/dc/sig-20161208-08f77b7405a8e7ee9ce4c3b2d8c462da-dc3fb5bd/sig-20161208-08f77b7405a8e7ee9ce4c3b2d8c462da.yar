rule sig_20161208_08f77b7405a8e7ee9ce4c3b2d8c462da {
  meta:
    description = "datamaliciousorder - file 20161208_08f77b7405a8e7ee9ce4c3b2d8c462da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cfc71a2a98b960418a672ea07ece4445fefe19d1aa903bb9a9d1cbb2603ff0a"

  strings:
    $s1 = "c7 = new Date();vJOc7[\"setUTC\"+\"FullYear\"](\"2003\");if (vJOc7.getUTCFullYear().toString(10) == \"2003\") {var vEv1 = vEQd6." ascii
    $s2 = "var vECq7 = new Function(\"vEQd6\", '{return vEQd6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGCz9 = new Function(\"vE" ascii
    $s3 = "###\"); return vEv1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vECq7 = new Function(\"vEQd6\", '{return vEQd6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGCz9 = new Function(\"vE" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}