rule sig_20161207_4ebb104168e74a82f9802afdf1b826a9 {
  meta:
    description = "datamaliciousorder - file 20161207_4ebb104168e74a82f9802afdf1b826a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d84db3f81b7a904c5bdc9ccc9a71eb1eff11037f57ec42cae003295c5795de92"

  strings:
    $s1 = "var vEIc3 = new Function(\"vUYw5\", '{var vRGd9 = new Date();vRGd9[\"setUTCFullYear\"](\"2003\");if (vRGd9.getUTCFullYear().toSt" ascii
    $s2 = "var vEIc3 = new Function(\"vUYw5\", '{var vRGd9 = new Date();vRGd9[\"setUTCFullYear\"](\"2003\");if (vRGd9.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vYz1 = vUYw5.split(\"###\"); return vYz1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vQMm8 = new Function(\"vUYw5\", '{return vUYw5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}