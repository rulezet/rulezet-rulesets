rule sig_20161207_a6b64f9ce025a6678f7252de1d129ed8 {
  meta:
    description = "datamaliciousorder - file 20161207_a6b64f9ce025a6678f7252de1d129ed8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd6d049a0c904624e029c6e732ea8a4052d6f0d17efabc92ae6761a8be39ca27"

  strings:
    $s1 = "var vBNw2 = new Function(\"vQs1\", '{var vMAu3 = new Date();vMAu3[\"setUTCFullYear\"](\"2003\");if (vMAu3.getUTCFullYear().toStr" ascii
    $s2 = "var vBNw2 = new Function(\"vQs1\", '{var vMAu3 = new Date();vMAu3[\"setUTCFullYear\"](\"2003\");if (vMAu3.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vUg4 = vQs1.split(\"###\"); return vUg4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vXj3 = new Function(\"vQs1\", '{return vQs1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}