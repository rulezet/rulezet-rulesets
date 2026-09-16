rule sig_20161208_80e1441090b44980532774f8f17906ee {
  meta:
    description = "datamaliciousorder - file 20161208_80e1441090b44980532774f8f17906ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2c02a17ec71f060e5a12464ecae94bf6079829a3516e1e56244bd16bf22a362"

  strings:
    $s1 = "var vFSa5 = new Function(\"vWAd7\", '{return vWAd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBs4 = new Function(\"vWA" ascii
    $s2 = "1 = new Date();vRTu1[\"setUTC\"+\"FullYear\"](\"2003\");if (vRTu1.getUTCFullYear().toString(10) == \"2003\") {var vHYk8 = vWAd7." ascii
    $s3 = "###\"); return vHYk8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFSa5 = new Function(\"vWAd7\", '{return vWAd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBs4 = new Function(\"vWA" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}