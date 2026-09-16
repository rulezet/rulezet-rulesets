rule sig_20161207_52156deceeeabce10e85155bd9885321 {
  meta:
    description = "datamaliciousorder - file 20161207_52156deceeeabce10e85155bd9885321.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3457659c44b5869159cd5c7a0fa8103c6805812ef7207a7022e91d1c61f34f18"

  strings:
    $s1 = "var vFWt3 = new Function(\"vMq7\", '{var vXDz2 = new Date();vXDz2[\"setUTCFullYear\"](\"2003\");if (vXDz2.getUTCFullYear().toStr" ascii
    $s2 = "var vFWt3 = new Function(\"vMq7\", '{var vXDz2 = new Date();vXDz2[\"setUTCFullYear\"](\"2003\");if (vXDz2.getUTCFullYear().toStr" ascii
    $s3 = "var vWMb2 = new Function(\"vMq7\", '{return vMq7.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vLs9 = vMq7.split(\"###\"); return vLs9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}