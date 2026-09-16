rule sig_20161207_bfae1a6ac1c25bb71076763cdf3f184e {
  meta:
    description = "datamaliciousorder - file 20161207_bfae1a6ac1c25bb71076763cdf3f184e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a90b39767dd0ad68ca487bf23f10332b0266002d5c6f8d4f0ca841bc923d7f1d"

  strings:
    $s1 = " new Date();vQr2[\"setUTCFullYear\"](\"2003\");if (vQr2.getUTCFullYear().toString(10) == \"2003\") {var vYd9 = vIn9.split(\"####" ascii
    $s2 = "var vNXg5 = new Function(\"vIn9\", '{return vIn9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMMs2 = new Function(\"vIn9" ascii
    $s3 = "var vNXg5 = new Function(\"vIn9\", '{return vIn9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMMs2 = new Function(\"vIn9" ascii
    $s4 = "urn vYd9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}