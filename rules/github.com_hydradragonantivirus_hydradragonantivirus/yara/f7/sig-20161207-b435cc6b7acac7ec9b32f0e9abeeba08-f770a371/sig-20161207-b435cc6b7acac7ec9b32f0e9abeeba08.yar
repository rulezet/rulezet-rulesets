rule sig_20161207_b435cc6b7acac7ec9b32f0e9abeeba08 {
  meta:
    description = "datamaliciousorder - file 20161207_b435cc6b7acac7ec9b32f0e9abeeba08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42dd24b628b90cf884dbac2f05264291c2bab93285cdf4ad9f8fe9e9c080177e"

  strings:
    $s1 = " = new Date();vTc6[\"setUTCFullYear\"](\"2003\");if (vTc6.getUTCFullYear().toString(10) == \"2003\") {var vNQf7 = vHPe7.split(\"" ascii
    $s2 = "var vGe0 = new Function(\"vHPe7\", '{return vHPe7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNNy0 = new Function(\"vHP" ascii
    $s3 = "var vGe0 = new Function(\"vHPe7\", '{return vHPe7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNNy0 = new Function(\"vHP" ascii
    $s4 = " return vNQf7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}