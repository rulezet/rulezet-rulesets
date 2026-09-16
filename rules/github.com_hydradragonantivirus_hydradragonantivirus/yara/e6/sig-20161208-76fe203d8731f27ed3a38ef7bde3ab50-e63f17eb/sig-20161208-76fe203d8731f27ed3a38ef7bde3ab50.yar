rule sig_20161208_76fe203d8731f27ed3a38ef7bde3ab50 {
  meta:
    description = "datamaliciousorder - file 20161208_76fe203d8731f27ed3a38ef7bde3ab50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c60d5a0197a3bb0d9658955772f6cd61942a1ea425b47e2d65f70d61fa448732"

  strings:
    $s1 = " new Date();vWQs0[\"setUTC\"+\"FullYear\"](\"2003\");if (vWQs0.getUTCFullYear().toString(10) == \"2003\") {var vTWi8 = vWa7.spli" ascii
    $s2 = "var vLYi5 = new Function(\"vWa7\", '{return vWa7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIh9 = new Function(\"vWa7" ascii
    $s3 = "); return vTWi8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vLYi5 = new Function(\"vWa7\", '{return vWa7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIh9 = new Function(\"vWa7" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}