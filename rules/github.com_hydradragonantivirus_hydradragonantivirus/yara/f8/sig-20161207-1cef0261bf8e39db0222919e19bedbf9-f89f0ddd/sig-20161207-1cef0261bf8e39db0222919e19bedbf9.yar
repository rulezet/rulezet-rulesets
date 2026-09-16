rule sig_20161207_1cef0261bf8e39db0222919e19bedbf9 {
  meta:
    description = "datamaliciousorder - file 20161207_1cef0261bf8e39db0222919e19bedbf9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "613205bf93f3c7154b485c621c16523d5982c8a232f08d33efcdbc669b7856aa"

  strings:
    $s1 = "var vJRc9 = new Function(\"vYIf5\", '{var vJx7 = new Date();vJx7[\"setUTCFullYear\"](\"2003\");if (vJx7.getUTCFullYear().toStrin" ascii
    $s2 = "var vJRc9 = new Function(\"vYIf5\", '{var vJx7 = new Date();vJx7[\"setUTCFullYear\"](\"2003\");if (vJx7.getUTCFullYear().toStrin" ascii
    $s3 = "var vAb6 = new Function(\"vYIf5\", '{return vYIf5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vVQq1 = vYIf5.split(\"###\"); return vVQq1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}