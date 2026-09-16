rule sig_20161207_3897e7f17198f02238b6603694f7297f {
  meta:
    description = "datamaliciousorder - file 20161207_3897e7f17198f02238b6603694f7297f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea592171405f955bbe6d5e6d192673cca27b02d79c6340718714bfaa0dac977"

  strings:
    $s1 = "var vDOo5 = new Function(\"vQYs7\", '{var vZx7 = new Date();vZx7[\"setUTCFullYear\"](\"2003\");if (vZx7.getUTCFullYear().toStrin" ascii
    $s2 = "var vDOo5 = new Function(\"vQYs7\", '{var vZx7 = new Date();vZx7[\"setUTCFullYear\"](\"2003\");if (vZx7.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vDa0 = vQYs7.split(\"###\"); return vDa0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vCMb5 = new Function(\"vQYs7\", '{return vQYs7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}