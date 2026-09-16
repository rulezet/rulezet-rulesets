rule sig_20161208_b71093846cba629cc69dc423063f330a {
  meta:
    description = "datamaliciousorder - file 20161208_b71093846cba629cc69dc423063f330a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c254f51a891bc4e4bd39f24f8bded1087e4cc3700a0619c112af04e7d25176b9"

  strings:
    $s1 = "var vVe7 = new Function(\"vXYp5\", '{return vXYp5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDNy3 = new Function(\"vXY" ascii
    $s2 = "0 = new Date();vZFe0[\"setUTC\"+\"FullYear\"](\"2003\");if (vZFe0.getUTCFullYear().toString(10) == \"2003\") {var vVQo7 = vXYp5." ascii
    $s3 = "###\"); return vVQo7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVe7 = new Function(\"vXYp5\", '{return vXYp5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDNy3 = new Function(\"vXY" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}