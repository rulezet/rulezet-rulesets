rule sig_20161207_588083da0609e5273ba5df7597b6e8be {
  meta:
    description = "datamaliciousorder - file 20161207_588083da0609e5273ba5df7597b6e8be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d6100cefeb7492f3cfdaf5c8a11628171a792503a5e2c0471632f9a8fd086f8"

  strings:
    $s1 = "= new Date();vGq5[\"setUTCFullYear\"](\"2003\");if (vGq5.getUTCFullYear().toString(10) == \"2003\") {var vMe9 = vOMg1.split(\"##" ascii
    $s2 = "var vUo2 = new Function(\"vOMg1\", '{return vOMg1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUk7 = new Function(\"vOMg" ascii
    $s3 = "eturn vMe9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUo2 = new Function(\"vOMg1\", '{return vOMg1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUk7 = new Function(\"vOMg" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}