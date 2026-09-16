rule sig_20161207_ec16f6829731550abab58ddc511c7243 {
  meta:
    description = "datamaliciousorder - file 20161207_ec16f6829731550abab58ddc511c7243.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58e2bc4cd66d6d81eda117dd3b75c8878cee3c7468780b14a7add9dd86a4ebcd"

  strings:
    $s1 = "var vSHs5 = new Function(\"vSv3\", '{var vNq4 = new Date();vNq4[\"setUTCFullYear\"](\"2003\");if (vNq4.getUTCFullYear().toString" ascii
    $s2 = "var vSHs5 = new Function(\"vSv3\", '{var vNq4 = new Date();vNq4[\"setUTCFullYear\"](\"2003\");if (vNq4.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vJJb4 = vSv3.split(\"###\"); return vJJb4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBu4 = new Function(\"vSv3\", '{return vSv3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}