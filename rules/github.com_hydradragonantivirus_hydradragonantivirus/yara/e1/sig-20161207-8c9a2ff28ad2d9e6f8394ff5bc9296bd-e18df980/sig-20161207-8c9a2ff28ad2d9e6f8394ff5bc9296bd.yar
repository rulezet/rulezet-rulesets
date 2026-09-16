rule sig_20161207_8c9a2ff28ad2d9e6f8394ff5bc9296bd {
  meta:
    description = "datamaliciousorder - file 20161207_8c9a2ff28ad2d9e6f8394ff5bc9296bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7351e0b9d7c255b2415d5de5d94a1193cf21f38018013eefe7029fe25231f8f1"

  strings:
    $s1 = "var vIQw6 = new Function(\"vEk5\", '{var vWz3 = new Date();vWz3[\"setUTCFullYear\"](\"2003\");if (vWz3.getUTCFullYear().toString" ascii
    $s2 = "var vIQw6 = new Function(\"vEk5\", '{var vWz3 = new Date();vWz3[\"setUTCFullYear\"](\"2003\");if (vWz3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vESz7 = vEk5.split(\"###\"); return vESz7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vHw8 = new Function(\"vEk5\", '{return vEk5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}