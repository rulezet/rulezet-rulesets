rule sig_20161208_527de523a3fa714aa99fb0bae33de719 {
  meta:
    description = "datamaliciousorder - file 20161208_527de523a3fa714aa99fb0bae33de719.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a2dadac7995b8764cdf5c53033a5a591c1dbc7c2f4dd5e17819995981af0cb6"

  strings:
    $s1 = "j4 = new Date();vULj4[\"setUTC\"+\"FullYear\"](\"2003\");if (vULj4.getUTCFullYear().toString(10) == \"2003\") {var vONt6 = vIKo1" ascii
    $s2 = "var vFJg3 = new Function(\"vIKo1\", '{return vIKo1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vETu6 = new Function(\"vI" ascii
    $s3 = "####\"); return vONt6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFJg3 = new Function(\"vIKo1\", '{return vIKo1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vETu6 = new Function(\"vI" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}