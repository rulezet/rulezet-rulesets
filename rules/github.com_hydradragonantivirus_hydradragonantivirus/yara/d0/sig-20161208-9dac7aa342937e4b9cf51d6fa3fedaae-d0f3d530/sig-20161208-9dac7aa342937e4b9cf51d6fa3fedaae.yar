rule sig_20161208_9dac7aa342937e4b9cf51d6fa3fedaae {
  meta:
    description = "datamaliciousorder - file 20161208_9dac7aa342937e4b9cf51d6fa3fedaae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebf31b53140e7ea5ce02e0d19bd5560b1ab8079873bcea92049559312ff37c94"

  strings:
    $s1 = "var vXQr7 = new Function(\"vDYr4\", '{return vDYr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vILq6 = new Function(\"vD" ascii
    $s2 = "g0 = new Date();vSWg0[\"setUTC\"+\"FullYear\"](\"2003\");if (vSWg0.getUTCFullYear().toString(10) == \"2003\") {var vDr6 = vDYr4." ascii
    $s3 = "###\"); return vDr6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vXQr7 = new Function(\"vDYr4\", '{return vDYr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vILq6 = new Function(\"vD" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}