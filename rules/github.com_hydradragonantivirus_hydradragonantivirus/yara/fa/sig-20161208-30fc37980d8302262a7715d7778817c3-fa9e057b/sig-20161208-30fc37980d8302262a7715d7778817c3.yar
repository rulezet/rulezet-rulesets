rule sig_20161208_30fc37980d8302262a7715d7778817c3 {
  meta:
    description = "datamaliciousorder - file 20161208_30fc37980d8302262a7715d7778817c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b65774ea7b7c269fd6d144aa2a17db4eaf3cafa4559638a7bef3d6b30ce13db"

  strings:
    $s1 = "6 = new Date();vTv6[\"setUTC\"+\"FullYear\"](\"2003\");if (vTv6.getUTCFullYear().toString(10) == \"2003\") {var vZa9 = vHDf3.spl" ascii
    $s2 = "var vIMl1 = new Function(\"vHDf3\", '{return vHDf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJAq8 = new Function(\"vH" ascii
    $s3 = "\"); return vZa9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vIMl1 = new Function(\"vHDf3\", '{return vHDf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJAq8 = new Function(\"vH" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}