rule sig_20161208_7caa69a2d9379e2b6444ec4c77026e4d {
  meta:
    description = "datamaliciousorder - file 20161208_7caa69a2d9379e2b6444ec4c77026e4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b095a909077d8e13ef3cde4791d042746be0407cff1a26929763cc0d912415c9"

  strings:
    $s1 = "6 = new Date();vMZe6[\"setUTC\"+\"FullYear\"](\"2003\");if (vMZe6.getUTCFullYear().toString(10) == \"2003\") {var vCz5 = vFEk7.s" ascii
    $s2 = "var vPj3 = new Function(\"vFEk7\", '{return vFEk7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIIr0 = new Function(\"vFE" ascii
    $s3 = "var vPj3 = new Function(\"vFEk7\", '{return vFEk7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIIr0 = new Function(\"vFE" ascii
    $s4 = "##\"); return vCz5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}