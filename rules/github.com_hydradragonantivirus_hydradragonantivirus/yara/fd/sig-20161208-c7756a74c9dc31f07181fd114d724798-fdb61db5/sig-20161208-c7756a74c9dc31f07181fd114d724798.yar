rule sig_20161208_c7756a74c9dc31f07181fd114d724798 {
  meta:
    description = "datamaliciousorder - file 20161208_c7756a74c9dc31f07181fd114d724798.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5442246593cc7819045f2d5fcb82e4fabe3bca31e7a580292b1c21e44e15cf18"

  strings:
    $s1 = "var vCQs7 = new Function(\"vMu9\", '{return vMu9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQq4 = new Function(\"vMu9" ascii
    $s2 = " new Date();vOSz2[\"setUTC\"+\"FullYear\"](\"2003\");if (vOSz2.getUTCFullYear().toString(10) == \"2003\") {var vJm4 = vMu9.split" ascii
    $s3 = "; return vJm4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vCQs7 = new Function(\"vMu9\", '{return vMu9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQq4 = new Function(\"vMu9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}