rule sig_20161207_a7547d5e6fb39fdbc2f5356239e8ffdf {
  meta:
    description = "datamaliciousorder - file 20161207_a7547d5e6fb39fdbc2f5356239e8ffdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5078dd4e2aa82380028dcf2b44153fd45e5ba02c909ddffcc3a68c81551a8837"

  strings:
    $s1 = "var vZn3 = new Function(\"vPAd5\", '{var vSNl7 = new Date();vSNl7[\"setUTCFullYear\"](\"2003\");if (vSNl7.getUTCFullYear().toStr" ascii
    $s2 = "var vZn3 = new Function(\"vPAd5\", '{var vSNl7 = new Date();vSNl7[\"setUTCFullYear\"](\"2003\");if (vSNl7.getUTCFullYear().toStr" ascii
    $s3 = "var vVx1 = new Function(\"vPAd5\", '{return vPAd5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vSIh4 = vPAd5.split(\"###\"); return vSIh4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}