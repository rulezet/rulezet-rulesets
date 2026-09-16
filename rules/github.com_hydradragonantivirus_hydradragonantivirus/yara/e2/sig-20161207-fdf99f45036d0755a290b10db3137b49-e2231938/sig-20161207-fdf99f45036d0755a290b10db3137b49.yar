rule sig_20161207_fdf99f45036d0755a290b10db3137b49 {
  meta:
    description = "datamaliciousorder - file 20161207_fdf99f45036d0755a290b10db3137b49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de9b4a8f532c9b0f079d18c65b817d149e26cb59b48504b490f8b83133e389b9"

  strings:
    $s1 = "var vFBr3 = new Function(\"vXj9\", '{var vNg2 = new Date();vNg2[\"setUTCFullYear\"](\"2003\");if (vNg2.getUTCFullYear().toString" ascii
    $s2 = "var vFBr3 = new Function(\"vXj9\", '{var vNg2 = new Date();vNg2[\"setUTCFullYear\"](\"2003\");if (vNg2.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vHRk6 = vXj9.split(\"###\"); return vHRk6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vAMq5 = new Function(\"vXj9\", '{return vXj9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}