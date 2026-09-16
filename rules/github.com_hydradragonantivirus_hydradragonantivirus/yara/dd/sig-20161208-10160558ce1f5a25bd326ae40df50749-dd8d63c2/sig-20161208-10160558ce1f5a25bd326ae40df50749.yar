rule sig_20161208_10160558ce1f5a25bd326ae40df50749 {
  meta:
    description = "datamaliciousorder - file 20161208_10160558ce1f5a25bd326ae40df50749.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5584cbae2eb3b161ebb1c3959d9c68f9a9d8fb0794cf82e58d19441a7aa6ac9e"

  strings:
    $s1 = "4 = new Date();vYTd4[\"setUTC\"+\"FullYear\"](\"2003\");if (vYTd4.getUTCFullYear().toString(10) == \"2003\") {var vFc9 = vMDz7.s" ascii
    $s2 = "var vKUh2 = new Function(\"vMDz7\", '{return vMDz7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPf3 = new Function(\"vMD" ascii
    $s3 = "var vKUh2 = new Function(\"vMDz7\", '{return vMDz7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPf3 = new Function(\"vMD" ascii
    $s4 = "##\"); return vFc9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}