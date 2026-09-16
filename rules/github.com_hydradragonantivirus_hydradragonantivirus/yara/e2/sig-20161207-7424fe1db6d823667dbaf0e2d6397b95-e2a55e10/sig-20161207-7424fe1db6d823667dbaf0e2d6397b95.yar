rule sig_20161207_7424fe1db6d823667dbaf0e2d6397b95 {
  meta:
    description = "datamaliciousorder - file 20161207_7424fe1db6d823667dbaf0e2d6397b95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96e8e52a6908663504fa91625198e488ae52eb1f262c159f4d169b516d7fcd97"

  strings:
    $s1 = "var vSv8 = new Function(\"vLh6\", '{var vTGz6 = new Date();vTGz6[\"setUTCFullYear\"](\"2003\");if (vTGz6.getUTCFullYear().toStri" ascii
    $s2 = "var vSv8 = new Function(\"vLh6\", '{var vTGz6 = new Date();vTGz6[\"setUTCFullYear\"](\"2003\");if (vTGz6.getUTCFullYear().toStri" ascii
    $s3 = "var vOb4 = new Function(\"vLh6\", '{return vLh6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vTe7 = vLh6.split(\"###\"); return vTe7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}