rule sig_20161208_22351a7f3d875c3013107d01d149dfb2 {
  meta:
    description = "datamaliciousorder - file 20161208_22351a7f3d875c3013107d01d149dfb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70ea73b3c4d4e5b231e23dfdc0987800e103d5781a75bb5b0742142dfb2e4304"

  strings:
    $s1 = "var vSe9 = new Function(\"vIGr4\", '{return vIGr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRBh8 = new Function(\"vIG" ascii
    $s2 = "2 = new Date();vDHb2[\"setUTC\"+\"FullYear\"](\"2003\");if (vDHb2.getUTCFullYear().toString(10) == \"2003\") {var vYSp8 = vIGr4." ascii
    $s3 = "var vSe9 = new Function(\"vIGr4\", '{return vIGr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRBh8 = new Function(\"vIG" ascii
    $s4 = "###\"); return vYSp8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}