rule sig_20161208_c16d9a88d1fa3780edb8685e69a808ef {
  meta:
    description = "datamaliciousorder - file 20161208_c16d9a88d1fa3780edb8685e69a808ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5119f663d4de324e21d9d28c7ac47f164ef928456bcb44bee7ed4742b68c4a"

  strings:
    $s1 = "ew Date();vLr3[\"setUTC\"+\"FullYear\"](\"2003\");if (vLr3.getUTCFullYear().toString(10) == \"2003\") {var vEo2 = vEv2.split(\"#" ascii
    $s2 = "var vBy9 = new Function(\"vEv2\", '{return vEv2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBp6 = new Function(\"vEv2\"" ascii
    $s3 = "turn vEo2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBy9 = new Function(\"vEv2\", '{return vEv2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBp6 = new Function(\"vEv2\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}