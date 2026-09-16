rule sig_20161207_14a9e1ea5894a62953add39dd51a18fa {
  meta:
    description = "datamaliciousorder - file 20161207_14a9e1ea5894a62953add39dd51a18fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37a908af383789ac4c64ec153a45ceb078e0c9cd01e22a158815db7676298132"

  strings:
    $s1 = "var vGAm0 = new Function(\"vSn7\", '{return vSn7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZPe0 = new Function(\"vSn7" ascii
    $s2 = " new Date();vAt0[\"setUTCFullYear\"](\"2003\");if (vAt0.getUTCFullYear().toString(10) == \"2003\") {var vGr5 = vSn7.split(\"####" ascii
    $s3 = "urn vGr5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGAm0 = new Function(\"vSn7\", '{return vSn7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZPe0 = new Function(\"vSn7" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}