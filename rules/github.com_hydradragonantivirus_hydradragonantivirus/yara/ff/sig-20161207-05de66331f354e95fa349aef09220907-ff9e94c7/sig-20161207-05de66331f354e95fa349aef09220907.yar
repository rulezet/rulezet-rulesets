rule sig_20161207_05de66331f354e95fa349aef09220907 {
  meta:
    description = "datamaliciousorder - file 20161207_05de66331f354e95fa349aef09220907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3bdde8979ca95da338810ad6982e6c8c0e583b2f101ad02a5abe6b9582535fd"

  strings:
    $s1 = "new Date();vHz2[\"setUTCFullYear\"](\"2003\");if (vHz2.getUTCFullYear().toString(10) == \"2003\") {var vDMb3 = vPk9.split(\"####" ascii
    $s2 = "var vZMg9 = new Function(\"vPk9\", '{return vPk9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLw0 = new Function(\"vPk9" ascii
    $s3 = "urn vDMb3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vZMg9 = new Function(\"vPk9\", '{return vPk9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLw0 = new Function(\"vPk9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}