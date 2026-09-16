rule sig_20161207_4860c3b33b98cbcb8c6dbfbc146eb473 {
  meta:
    description = "datamaliciousorder - file 20161207_4860c3b33b98cbcb8c6dbfbc146eb473.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8095ded3ea74b77af6524fe7bd61f8eae1a002ba5cd4cabed7200e76e7323c33"

  strings:
    $s1 = "var vQSp1 = new Function(\"vUAp9\", '{return vUAp9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZj6 = new Function(\"vUA" ascii
    $s2 = "4 = new Date();vAAh4[\"setUTCFullYear\"](\"2003\");if (vAAh4.getUTCFullYear().toString(10) == \"2003\") {var vFAn1 = vUAp9.split" ascii
    $s3 = "var vQSp1 = new Function(\"vUAp9\", '{return vUAp9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZj6 = new Function(\"vUA" ascii
    $s4 = "\"); return vFAn1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}