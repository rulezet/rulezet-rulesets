rule sig_20161208_35560e859b6b20a7813ca14fddfdf26d {
  meta:
    description = "datamaliciousorder - file 20161208_35560e859b6b20a7813ca14fddfdf26d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "423eb7baf14e44d21b68e6cbbe375f8abec3b244f8dffcaff846044ad24129d4"

  strings:
    $s1 = "new Date();vYv1[\"setUTC\"+\"FullYear\"](\"2003\");if (vYv1.getUTCFullYear().toString(10) == \"2003\") {var vPMo2 = vSj3.split(" ascii
    $s2 = "var vBZr2 = new Function(\"vSj3\", '{return vSj3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGh1 = new Function(\"vSj3" ascii
    $s3 = "var vBZr2 = new Function(\"vSj3\", '{return vSj3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGh1 = new Function(\"vSj3" ascii
    $s4 = "return vPMo2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}