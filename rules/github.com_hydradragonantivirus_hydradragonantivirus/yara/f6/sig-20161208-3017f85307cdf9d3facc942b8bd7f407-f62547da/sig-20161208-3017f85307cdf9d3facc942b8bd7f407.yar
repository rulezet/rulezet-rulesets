rule sig_20161208_3017f85307cdf9d3facc942b8bd7f407 {
  meta:
    description = "datamaliciousorder - file 20161208_3017f85307cdf9d3facc942b8bd7f407.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58360ada82460e4e6776d8823f01cc8ea317e9621be9489f648e28ba6068ce0f"

  strings:
    $s1 = "var vGv1 = new Function(\"vEPl3\", '{return vEPl3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQd9 = new Function(\"vEPl" ascii
    $s2 = "= new Date();vXm4[\"setUTC\"+\"FullYear\"](\"2003\");if (vXm4.getUTCFullYear().toString(10) == \"2003\") {var vZFr2 = vEPl3.spli" ascii
    $s3 = "); return vZFr2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGv1 = new Function(\"vEPl3\", '{return vEPl3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQd9 = new Function(\"vEPl" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}