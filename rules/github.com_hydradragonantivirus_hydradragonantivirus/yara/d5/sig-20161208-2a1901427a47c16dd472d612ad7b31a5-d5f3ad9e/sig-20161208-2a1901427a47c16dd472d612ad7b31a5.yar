rule sig_20161208_2a1901427a47c16dd472d612ad7b31a5 {
  meta:
    description = "datamaliciousorder - file 20161208_2a1901427a47c16dd472d612ad7b31a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eb867729a7b0ccce2d3d7eb19ea13ca165a51b29f5a0e013dbd3047babdcbf9"

  strings:
    $s1 = "var vTBf8 = new Function(\"vDw3\", '{return vDw3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMIe5 = new Function(\"vDw3" ascii
    $s2 = " new Date();vJk6[\"setUTC\"+\"FullYear\"](\"2003\");if (vJk6.getUTCFullYear().toString(10) == \"2003\") {var vGUd9 = vDw3.split(" ascii
    $s3 = " return vGUd9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTBf8 = new Function(\"vDw3\", '{return vDw3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMIe5 = new Function(\"vDw3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}