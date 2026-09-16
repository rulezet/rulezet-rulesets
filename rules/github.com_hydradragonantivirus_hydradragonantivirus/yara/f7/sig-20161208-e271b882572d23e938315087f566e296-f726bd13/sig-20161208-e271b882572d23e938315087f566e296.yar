rule sig_20161208_e271b882572d23e938315087f566e296 {
  meta:
    description = "datamaliciousorder - file 20161208_e271b882572d23e938315087f566e296.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1231fec55cc00138e57e0507f513138ff5fb95d5ff2f18fad150dea1bc1c117f"

  strings:
    $s1 = "var vVFn5 = new Function(\"vVRm0\", '{return vVRm0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vITg8 = new Function(\"vV" ascii
    $s2 = "6 = new Date();vHn6[\"setUTC\"+\"FullYear\"](\"2003\");if (vHn6.getUTCFullYear().toString(10) == \"2003\") {var vMJr5 = vVRm0.sp" ascii
    $s3 = "#\"); return vMJr5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVFn5 = new Function(\"vVRm0\", '{return vVRm0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vITg8 = new Function(\"vV" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}