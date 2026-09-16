rule sig_20161207_4ca8440c9d690bc4a8035ed2f0dbe3b6 {
  meta:
    description = "datamaliciousorder - file 20161207_4ca8440c9d690bc4a8035ed2f0dbe3b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f356832eeee735129e36a649b4b778c97f9843433b23963c3a55b1d8cc6dee42"

  strings:
    $s1 = "var vTr5 = new Function(\"vQu7\", '{var vPx4 = new Date();vPx4[\"setUTCFullYear\"](\"2003\");if (vPx4.getUTCFullYear().toString(" ascii
    $s2 = "var vTr5 = new Function(\"vQu7\", '{var vPx4 = new Date();vPx4[\"setUTCFullYear\"](\"2003\");if (vPx4.getUTCFullYear().toString(" ascii
    $s3 = "var vVWe2 = new Function(\"vQu7\", '{return vQu7.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vBWi8 = vQu7.split(\"###\"); return vBWi8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}