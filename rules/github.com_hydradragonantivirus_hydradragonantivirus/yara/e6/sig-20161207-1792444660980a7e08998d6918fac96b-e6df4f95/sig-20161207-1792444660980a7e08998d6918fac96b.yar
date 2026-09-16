rule sig_20161207_1792444660980a7e08998d6918fac96b {
  meta:
    description = "datamaliciousorder - file 20161207_1792444660980a7e08998d6918fac96b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3b041168cd0d90f648b503b30ae8ac3a9f7003699d2f1e3aba4315954ca55c1"

  strings:
    $s1 = "new Date();vKOm3[\"setUTCFullYear\"](\"2003\");if (vKOm3.getUTCFullYear().toString(10) == \"2003\") {var vVc0 = vJm2.split(\"###" ascii
    $s2 = "var vQr3 = new Function(\"vJm2\", '{return vJm2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPp8 = new Function(\"vJm2\"" ascii
    $s3 = "var vQr3 = new Function(\"vJm2\", '{return vJm2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPp8 = new Function(\"vJm2\"" ascii
    $s4 = "turn vVc0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}