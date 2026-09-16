rule sig_20161207_dffbe9aa1dc2ce7c446c285ff96403e8 {
  meta:
    description = "datamaliciousorder - file 20161207_dffbe9aa1dc2ce7c446c285ff96403e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d94a22269a9eaab13f0761ae9480e59a9e78df7d54226c5d6fcfddedec9160b"

  strings:
    $s1 = "var vSZz5 = new Function(\"vJa8\", '{return vJa8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIEe8 = new Function(\"vJa8" ascii
    $s2 = " new Date();vWu1[\"setUTCFullYear\"](\"2003\");if (vWu1.getUTCFullYear().toString(10) == \"2003\") {var vDv0 = vJa8.split(\"####" ascii
    $s3 = "var vSZz5 = new Function(\"vJa8\", '{return vJa8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIEe8 = new Function(\"vJa8" ascii
    $s4 = "urn vDv0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}