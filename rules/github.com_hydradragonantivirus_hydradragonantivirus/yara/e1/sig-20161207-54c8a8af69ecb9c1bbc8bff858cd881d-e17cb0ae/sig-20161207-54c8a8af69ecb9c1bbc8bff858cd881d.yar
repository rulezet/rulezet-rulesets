rule sig_20161207_54c8a8af69ecb9c1bbc8bff858cd881d {
  meta:
    description = "datamaliciousorder - file 20161207_54c8a8af69ecb9c1bbc8bff858cd881d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95dbb68449b7a2c2dc1a181d0261ffb9598be9a2961131e15aafb2c930386cde"

  strings:
    $s1 = " new Date();vTt8[\"setUTCFullYear\"](\"2003\");if (vTt8.getUTCFullYear().toString(10) == \"2003\") {var vJl2 = vNr8.split(\"####" ascii
    $s2 = "var vDGm3 = new Function(\"vNr8\", '{return vNr8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBQq6 = new Function(\"vNr8" ascii
    $s3 = "var vDGm3 = new Function(\"vNr8\", '{return vNr8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBQq6 = new Function(\"vNr8" ascii
    $s4 = "urn vJl2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}