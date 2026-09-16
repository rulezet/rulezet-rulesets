rule sig_20161208_45e32ab2c7a806d19ad841e0c326e473 {
  meta:
    description = "datamaliciousorder - file 20161208_45e32ab2c7a806d19ad841e0c326e473.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "067e3197364f96ddbd23ddbcc1164c8a05a0bb5ce0b9e364a9611e6d2719bd54"

  strings:
    $s1 = "4 = new Date();vOTd4[\"setUTC\"+\"FullYear\"](\"2003\");if (vOTd4.getUTCFullYear().toString(10) == \"2003\") {var vKo1 = vLNg2.s" ascii
    $s2 = "var vVi6 = new Function(\"vLNg2\", '{return vLNg2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCJp3 = new Function(\"vLN" ascii
    $s3 = "var vVi6 = new Function(\"vLNg2\", '{return vLNg2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCJp3 = new Function(\"vLN" ascii
    $s4 = "##\"); return vKo1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}