rule sig_20161207_53f5d2a92c2237df679f5890341e218a {
  meta:
    description = "datamaliciousorder - file 20161207_53f5d2a92c2237df679f5890341e218a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "155fa3a6ce986f9fff11070702286b8dcbe47c99b1d7bcf83d7de8f991d7a3b4"

  strings:
    $s1 = "var vWi0 = new Function(\"vHKm7\", '{var vARy7 = new Date();vARy7[\"setUTCFullYear\"](\"2003\");if (vARy7.getUTCFullYear().toStr" ascii
    $s2 = "var vWi0 = new Function(\"vHKm7\", '{var vARy7 = new Date();vARy7[\"setUTCFullYear\"](\"2003\");if (vARy7.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vFj1 = vHKm7.split(\"###\"); return vFj1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vCv5 = new Function(\"vHKm7\", '{return vHKm7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}