rule sig_20161207_0d594788aa2d26c509ef41ba5101377b {
  meta:
    description = "datamaliciousorder - file 20161207_0d594788aa2d26c509ef41ba5101377b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01cfa0ff0db32e788854bf26a6c3864858d33be05da785bb9f5340908ec0f6dc"

  strings:
    $s1 = "var vPo8 = new Function(\"vHAw3\", '{var vOe8 = new Date();vOe8[\"setUTCFullYear\"](\"2003\");if (vOe8.getUTCFullYear().toString" ascii
    $s2 = "var vPo8 = new Function(\"vHAw3\", '{var vOe8 = new Date();vOe8[\"setUTCFullYear\"](\"2003\");if (vOe8.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vNWy1 = vHAw3.split(\"###\"); return vNWy1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vEEo4 = new Function(\"vHAw3\", '{return vHAw3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}