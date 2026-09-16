rule sig_20161207_af45a2959be3ba6c88ffcd6bd6a75314 {
  meta:
    description = "datamaliciousorder - file 20161207_af45a2959be3ba6c88ffcd6bd6a75314.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "985cb02422f2be960890a64bfd89fd7b8f65e4fd8352ef13552480f8e5c30b01"

  strings:
    $s1 = "var vKe4 = new Function(\"vHTl4\", '{var vHIb4 = new Date();vHIb4[\"setUTCFullYear\"](\"2003\");if (vHIb4.getUTCFullYear().toStr" ascii
    $s2 = "var vKe4 = new Function(\"vHTl4\", '{var vHIb4 = new Date();vHIb4[\"setUTCFullYear\"](\"2003\");if (vHIb4.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vZm3 = vHTl4.split(\"###\"); return vZm3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWv1 = new Function(\"vHTl4\", '{return vHTl4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}