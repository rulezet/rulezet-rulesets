rule sig_20161207_0289be90b3a4d4a5c224e4b7b13ff0f7 {
  meta:
    description = "datamaliciousorder - file 20161207_0289be90b3a4d4a5c224e4b7b13ff0f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ea00a2f8993398a0489accc1a210d71f7feeb3f54968b2fdd73cacd7ceaa409"

  strings:
    $s1 = "var vIh7 = new Function(\"vYPm1\", '{var vIZj5 = new Date();vIZj5[\"setUTCFullYear\"](\"2003\");if (vIZj5.getUTCFullYear().toStr" ascii
    $s2 = "var vIh7 = new Function(\"vYPm1\", '{var vIZj5 = new Date();vIZj5[\"setUTCFullYear\"](\"2003\");if (vIZj5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vHJa3 = vYPm1.split(\"###\"); return vHJa3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vXg7 = new Function(\"vYPm1\", '{return vYPm1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}