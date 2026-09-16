rule sig_20161207_98e96e0b36ba3cf38ca98dcd96c277aa {
  meta:
    description = "datamaliciousorder - file 20161207_98e96e0b36ba3cf38ca98dcd96c277aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bd132a592c77d25a383ca522fd6581e7a0e3c95e22eff64d4e0e2d678d63861"

  strings:
    $s1 = "2 = new Date();vFo2[\"setUTCFullYear\"](\"2003\");if (vFo2.getUTCFullYear().toString(10) == \"2003\") {var vLZy0 = vSOu9.split(" ascii
    $s2 = "var vSRd1 = new Function(\"vSOu9\", '{return vSOu9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKEq4 = new Function(\"vS" ascii
    $s3 = "; return vLZy0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSRd1 = new Function(\"vSOu9\", '{return vSOu9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKEq4 = new Function(\"vS" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}