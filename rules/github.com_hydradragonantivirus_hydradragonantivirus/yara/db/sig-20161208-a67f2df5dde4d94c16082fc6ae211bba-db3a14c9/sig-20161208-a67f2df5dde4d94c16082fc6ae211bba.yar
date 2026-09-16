rule sig_20161208_a67f2df5dde4d94c16082fc6ae211bba {
  meta:
    description = "datamaliciousorder - file 20161208_a67f2df5dde4d94c16082fc6ae211bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7a4b6ef604dbf17f7f0ee58ad631ffa9d245d34c28c5b9ec1697c7460356afd"

  strings:
    $s1 = "var vPEb0 = new Function(\"vAs1\", '{return vAs1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRr0 = new Function(\"vAs1" ascii
    $s2 = "new Date();vWd2[\"setUTC\"+\"FullYear\"](\"2003\");if (vWd2.getUTCFullYear().toString(10) == \"2003\") {var vBo4 = vAs1.split(\"" ascii
    $s3 = "var vPEb0 = new Function(\"vAs1\", '{return vAs1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRr0 = new Function(\"vAs1" ascii
    $s4 = "eturn vBo4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}