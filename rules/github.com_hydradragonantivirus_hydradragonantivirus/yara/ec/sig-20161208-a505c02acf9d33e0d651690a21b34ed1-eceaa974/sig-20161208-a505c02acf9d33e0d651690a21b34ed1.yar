rule sig_20161208_a505c02acf9d33e0d651690a21b34ed1 {
  meta:
    description = "datamaliciousorder - file 20161208_a505c02acf9d33e0d651690a21b34ed1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "301aa24dff694e0c3fd8af5e25af5c6b1329646811dccd173da847b2c69617d0"

  strings:
    $s1 = "var vVQg1 = new Function(\"vYr2\", '{return vYr2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWZl7 = new Function(\"vYr2" ascii
    $s2 = " new Date();vYx6[\"setUTC\"+\"FullYear\"](\"2003\");if (vYx6.getUTCFullYear().toString(10) == \"2003\") {var vDv0 = vYr2.split(" ascii
    $s3 = "var vVQg1 = new Function(\"vYr2\", '{return vYr2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWZl7 = new Function(\"vYr2" ascii
    $s4 = "return vDv0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}