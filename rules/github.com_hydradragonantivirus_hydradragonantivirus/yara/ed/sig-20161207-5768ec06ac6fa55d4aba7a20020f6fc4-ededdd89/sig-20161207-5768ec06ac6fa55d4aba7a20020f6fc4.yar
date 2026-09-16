rule sig_20161207_5768ec06ac6fa55d4aba7a20020f6fc4 {
  meta:
    description = "datamaliciousorder - file 20161207_5768ec06ac6fa55d4aba7a20020f6fc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96527ea94091cdbfbb8ffa328faa90314d59f78251b2302560385f31a5240979"

  strings:
    $s1 = "ew Date();vCd3[\"setUTCFullYear\"](\"2003\");if (vCd3.getUTCFullYear().toString(10) == \"2003\") {var vOe4 = vUf2.split(\"####\"" ascii
    $s2 = "var vOf5 = new Function(\"vUf2\", '{return vUf2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGi6 = new Function(\"vUf2\"" ascii
    $s3 = "n vOe4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vOf5 = new Function(\"vUf2\", '{return vUf2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGi6 = new Function(\"vUf2\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}