rule sig_20161207_32c6758ba4fbd7e518aabd94fc6e1be3 {
  meta:
    description = "datamaliciousorder - file 20161207_32c6758ba4fbd7e518aabd94fc6e1be3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d199a9e6e054bff3569edea6ce71b5bd51809d0a2b5ac8afceb6df9cfa147518"

  strings:
    $s1 = "var vGn1 = new Function(\"vXIc9\", '{return vXIc9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNu9 = new Function(\"vXIc" ascii
    $s2 = "= new Date();vZw5[\"setUTCFullYear\"](\"2003\");if (vZw5.getUTCFullYear().toString(10) == \"2003\") {var vMMj4 = vXIc9.split(\"#" ascii
    $s3 = "return vMMj4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGn1 = new Function(\"vXIc9\", '{return vXIc9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNu9 = new Function(\"vXIc" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}