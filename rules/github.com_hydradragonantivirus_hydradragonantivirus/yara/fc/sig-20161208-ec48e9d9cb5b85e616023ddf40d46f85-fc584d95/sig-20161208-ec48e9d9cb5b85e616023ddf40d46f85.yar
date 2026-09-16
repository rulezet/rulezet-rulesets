rule sig_20161208_ec48e9d9cb5b85e616023ddf40d46f85 {
  meta:
    description = "datamaliciousorder - file 20161208_ec48e9d9cb5b85e616023ddf40d46f85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "959e412bec2c262ac3719c5331cfb5689bc55946b77ad6d30ca1a672fb9c4cac"

  strings:
    $s1 = " = new Date();vXYd0[\"setUTC\"+\"FullYear\"](\"2003\");if (vXYd0.getUTCFullYear().toString(10) == \"2003\") {var vYNk5 = vZMx8.s" ascii
    $s2 = "var vHj2 = new Function(\"vZMx8\", '{return vZMx8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXw7 = new Function(\"vZMx" ascii
    $s3 = "##\"); return vYNk5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vHj2 = new Function(\"vZMx8\", '{return vZMx8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXw7 = new Function(\"vZMx" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}