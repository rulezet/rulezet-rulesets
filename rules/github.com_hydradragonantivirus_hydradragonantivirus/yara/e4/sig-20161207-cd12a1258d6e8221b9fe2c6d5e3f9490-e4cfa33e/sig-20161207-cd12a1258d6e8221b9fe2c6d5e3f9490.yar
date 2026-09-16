rule sig_20161207_cd12a1258d6e8221b9fe2c6d5e3f9490 {
  meta:
    description = "datamaliciousorder - file 20161207_cd12a1258d6e8221b9fe2c6d5e3f9490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9094617422301cb6439cea2835d412c961edf9f7fff762ce482b06eb7f18d447"

  strings:
    $s1 = "var vEl5 = new Function(\"vSUw3\", '{return vSUw3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMKo1 = new Function(\"vSU" ascii
    $s2 = "1 = new Date();vLHv1[\"setUTCFullYear\"](\"2003\");if (vLHv1.getUTCFullYear().toString(10) == \"2003\") {var vSi3 = vSUw3.split(" ascii
    $s3 = "); return vSi3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEl5 = new Function(\"vSUw3\", '{return vSUw3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMKo1 = new Function(\"vSU" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}