rule sig_20161208_af4e72477fb9cf5486cbdc44c684f388 {
  meta:
    description = "datamaliciousorder - file 20161208_af4e72477fb9cf5486cbdc44c684f388.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd8f459f100b75fefe872c751dbde66f0b818e6447c1e61752071749c9052574"

  strings:
    $s1 = "var vNm5 = new Function(\"vRc4\", '{return vRc4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSEq1 = new Function(\"vRc4" ascii
    $s2 = " new Date();vBRt0[\"setUTC\"+\"FullYear\"](\"2003\");if (vBRt0.getUTCFullYear().toString(10) == \"2003\") {var vUw6 = vRc4.split" ascii
    $s3 = "var vNm5 = new Function(\"vRc4\", '{return vRc4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSEq1 = new Function(\"vRc4" ascii
    $s4 = "; return vUw6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}