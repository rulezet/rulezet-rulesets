rule sig_20161208_7841cc3128383d6448c3098d87ea1fa8 {
  meta:
    description = "datamaliciousorder - file 20161208_7841cc3128383d6448c3098d87ea1fa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34616e721c75d6470cae931c9120d2bedeb77a0cf12d0952a411114035ee08f0"

  strings:
    $s1 = "new Date();vVg0[\"setUTC\"+\"FullYear\"](\"2003\");if (vVg0.getUTCFullYear().toString(10) == \"2003\") {var vLNz8 = vQz0.split(" ascii
    $s2 = "var vIUr2 = new Function(\"vQz0\", '{return vQz0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTl7 = new Function(\"vQz0" ascii
    $s3 = "var vIUr2 = new Function(\"vQz0\", '{return vQz0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTl7 = new Function(\"vQz0" ascii
    $s4 = "return vLNz8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}