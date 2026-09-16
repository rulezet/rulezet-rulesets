rule sig_20161207_dd9c80450ee8268df53c44834022549e {
  meta:
    description = "datamaliciousorder - file 20161207_dd9c80450ee8268df53c44834022549e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26aed0b7e6c7a82f8436562d2c1340b2a81ae5f6ab182f169bc13fae47a77b97"

  strings:
    $s1 = " new Date();vPx3[\"setUTCFullYear\"](\"2003\");if (vPx3.getUTCFullYear().toString(10) == \"2003\") {var vLEy6 = vBj9.split(\"###" ascii
    $s2 = "var vATg0 = new Function(\"vBj9\", '{return vBj9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPLv8 = new Function(\"vBj9" ascii
    $s3 = "var vATg0 = new Function(\"vBj9\", '{return vBj9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPLv8 = new Function(\"vBj9" ascii
    $s4 = "turn vLEy6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}