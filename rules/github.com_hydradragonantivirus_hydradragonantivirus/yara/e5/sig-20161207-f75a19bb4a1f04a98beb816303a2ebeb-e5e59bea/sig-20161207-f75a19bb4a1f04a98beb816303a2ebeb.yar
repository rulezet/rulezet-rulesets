rule sig_20161207_f75a19bb4a1f04a98beb816303a2ebeb {
  meta:
    description = "datamaliciousorder - file 20161207_f75a19bb4a1f04a98beb816303a2ebeb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "413b5ae2c515c91420261d5eb1c587719c329df129d032a51874caa1fdca6721"

  strings:
    $s1 = "var vZHj9 = new Function(\"vSLz9\", '{var vVe2 = new Date();vVe2[\"setUTCFullYear\"](\"2003\");if (vVe2.getUTCFullYear().toStrin" ascii
    $s2 = "var vZHj9 = new Function(\"vSLz9\", '{var vVe2 = new Date();vVe2[\"setUTCFullYear\"](\"2003\");if (vVe2.getUTCFullYear().toStrin" ascii
    $s3 = "var vOMr7 = new Function(\"vSLz9\", '{return vSLz9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vId3 = vSLz9.split(\"###\"); return vId3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}