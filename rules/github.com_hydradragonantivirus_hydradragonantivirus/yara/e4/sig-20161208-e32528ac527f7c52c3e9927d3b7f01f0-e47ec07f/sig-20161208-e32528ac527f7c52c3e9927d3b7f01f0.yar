rule sig_20161208_e32528ac527f7c52c3e9927d3b7f01f0 {
  meta:
    description = "datamaliciousorder - file 20161208_e32528ac527f7c52c3e9927d3b7f01f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc961f5e7b9aaef0673a60a3ff2a260e24cc05fd52bb54c8e342712c1095bbc8"

  strings:
    $s1 = "var vNj1 = new Function(\"vBd6\", '{return vBd6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFWw3 = new Function(\"vBd6" ascii
    $s2 = " new Date();vVKb1[\"setUTC\"+\"FullYear\"](\"2003\");if (vVKb1.getUTCFullYear().toString(10) == \"2003\") {var vRt8 = vBd6.split" ascii
    $s3 = "var vNj1 = new Function(\"vBd6\", '{return vBd6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFWw3 = new Function(\"vBd6" ascii
    $s4 = "; return vRt8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}