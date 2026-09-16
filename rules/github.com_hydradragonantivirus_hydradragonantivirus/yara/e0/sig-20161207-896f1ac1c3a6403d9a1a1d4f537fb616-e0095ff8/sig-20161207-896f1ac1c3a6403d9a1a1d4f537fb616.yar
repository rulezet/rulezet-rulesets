rule sig_20161207_896f1ac1c3a6403d9a1a1d4f537fb616 {
  meta:
    description = "datamaliciousorder - file 20161207_896f1ac1c3a6403d9a1a1d4f537fb616.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "518900ce21152534202e6d69acc9372e7c86675d377acac839c7e9649057ed6d"

  strings:
    $s1 = "var vTSr6 = new Function(\"vHm3\", '{var vKj9 = new Date();vKj9[\"setUTCFullYear\"](\"2003\");if (vKj9.getUTCFullYear().toString" ascii
    $s2 = "var vTSr6 = new Function(\"vHm3\", '{var vKj9 = new Date();vKj9[\"setUTCFullYear\"](\"2003\");if (vKj9.getUTCFullYear().toString" ascii
    $s3 = "var vONk2 = new Function(\"vHm3\", '{return vHm3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vZo7 = vHm3.split(\"###\"); return vZo7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}