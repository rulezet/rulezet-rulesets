rule sig_20161207_2ca86245e815945ad354d22b3336fb44 {
  meta:
    description = "datamaliciousorder - file 20161207_2ca86245e815945ad354d22b3336fb44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f0539c465ee156c58a1e6cd826015b98ff04774461abecc8eca9d641e966985"

  strings:
    $s1 = "var vEr0 = new Function(\"vRZv8\", '{var vQd5 = new Date();vQd5[\"setUTCFullYear\"](\"2003\");if (vQd5.getUTCFullYear().toString" ascii
    $s2 = "var vEr0 = new Function(\"vRZv8\", '{var vQd5 = new Date();vQd5[\"setUTCFullYear\"](\"2003\");if (vQd5.getUTCFullYear().toString" ascii
    $s3 = "var vNu3 = new Function(\"vRZv8\", '{return vRZv8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vERl4 = vRZv8.split(\"###\"); return vERl4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}