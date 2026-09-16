rule sig_20161208_ae14099637edc4b897b83bffa6a5e5c1 {
  meta:
    description = "datamaliciousorder - file 20161208_ae14099637edc4b897b83bffa6a5e5c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad8a004b9195a8fcdbd629329cdc463898f0b083b39e7216113e9d27b68ce2f0"

  strings:
    $s1 = "var vXKx8 = new Function(\"vNRi3\", '{return vNRi3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKXv5 = new Function(\"vN" ascii
    $s2 = "9 = new Date();vBc9[\"setUTC\"+\"FullYear\"](\"2003\");if (vBc9.getUTCFullYear().toString(10) == \"2003\") {var vXYm2 = vNRi3.sp" ascii
    $s3 = "var vXKx8 = new Function(\"vNRi3\", '{return vNRi3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKXv5 = new Function(\"vN" ascii
    $s4 = "#\"); return vXYm2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}