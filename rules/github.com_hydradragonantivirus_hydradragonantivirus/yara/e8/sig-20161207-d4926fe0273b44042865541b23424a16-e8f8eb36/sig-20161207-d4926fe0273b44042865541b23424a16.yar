rule sig_20161207_d4926fe0273b44042865541b23424a16 {
  meta:
    description = "datamaliciousorder - file 20161207_d4926fe0273b44042865541b23424a16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "881f2784d5ff65c9b151456c6b40a1b1b8ad934e53768e8a87a4586b45d456d3"

  strings:
    $s1 = "var vYUd0 = new Function(\"vFTi1\", '{var vSAn0 = new Date();vSAn0[\"setUTCFullYear\"](\"2003\");if (vSAn0.getUTCFullYear().toSt" ascii
    $s2 = "var vYUd0 = new Function(\"vFTi1\", '{var vSAn0 = new Date();vSAn0[\"setUTCFullYear\"](\"2003\");if (vSAn0.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vOLl8 = vFTi1.split(\"###\"); return vOLl8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vGj5 = new Function(\"vFTi1\", '{return vFTi1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}