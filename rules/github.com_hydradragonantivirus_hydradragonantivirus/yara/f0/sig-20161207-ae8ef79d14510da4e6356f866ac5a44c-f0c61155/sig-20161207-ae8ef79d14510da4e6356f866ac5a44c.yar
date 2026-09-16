rule sig_20161207_ae8ef79d14510da4e6356f866ac5a44c {
  meta:
    description = "datamaliciousorder - file 20161207_ae8ef79d14510da4e6356f866ac5a44c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50ab4324a483c7b67cb7387338b1dea714b564d0fabe3e00fd5a24880aa1ba6d"

  strings:
    $s1 = "var vGCf6 = new Function(\"vKVq1\", '{return vKVq1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBAb8 = new Function(\"vK" ascii
    $s2 = "w4 = new Date();vNQw4[\"setUTCFullYear\"](\"2003\");if (vNQw4.getUTCFullYear().toString(10) == \"2003\") {var vRc2 = vKVq1.split" ascii
    $s3 = "var vGCf6 = new Function(\"vKVq1\", '{return vKVq1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBAb8 = new Function(\"vK" ascii
    $s4 = "\"); return vRc2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}