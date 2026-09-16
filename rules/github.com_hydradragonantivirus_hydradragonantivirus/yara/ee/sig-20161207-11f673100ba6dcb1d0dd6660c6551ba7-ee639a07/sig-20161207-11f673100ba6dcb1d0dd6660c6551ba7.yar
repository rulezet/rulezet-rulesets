rule sig_20161207_11f673100ba6dcb1d0dd6660c6551ba7 {
  meta:
    description = "datamaliciousorder - file 20161207_11f673100ba6dcb1d0dd6660c6551ba7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e4a9d4348f947b1f11aeb509056a98a9c468b5b0f667d735f344b239e8f4f80"

  strings:
    $s1 = "var vTu9 = new Function(\"vHXm5\", '{return vHXm5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOt6 = new Function(\"vHXm" ascii
    $s2 = "= new Date();vHj2[\"setUTCFullYear\"](\"2003\");if (vHj2.getUTCFullYear().toString(10) == \"2003\") {var vFZo6 = vHXm5.split(\"#" ascii
    $s3 = "return vFZo6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTu9 = new Function(\"vHXm5\", '{return vHXm5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOt6 = new Function(\"vHXm" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}