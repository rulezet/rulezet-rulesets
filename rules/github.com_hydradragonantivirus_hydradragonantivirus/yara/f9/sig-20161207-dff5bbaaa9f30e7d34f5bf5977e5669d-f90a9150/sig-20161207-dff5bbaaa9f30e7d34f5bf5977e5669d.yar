rule sig_20161207_dff5bbaaa9f30e7d34f5bf5977e5669d {
  meta:
    description = "datamaliciousorder - file 20161207_dff5bbaaa9f30e7d34f5bf5977e5669d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ec7af6ceba3e6c8f01172ff183217216cd6c9386ae68f15dd958bf3eba842ac"

  strings:
    $s1 = "var vVFz4 = new Function(\"vEc7\", '{var vOGy1 = new Date();vOGy1[\"setUTCFullYear\"](\"2003\");if (vOGy1.getUTCFullYear().toStr" ascii
    $s2 = "var vVFz4 = new Function(\"vEc7\", '{var vOGy1 = new Date();vOGy1[\"setUTCFullYear\"](\"2003\");if (vOGy1.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vCk8 = vEc7.split(\"###\"); return vCk8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vLd1 = new Function(\"vEc7\", '{return vEc7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}