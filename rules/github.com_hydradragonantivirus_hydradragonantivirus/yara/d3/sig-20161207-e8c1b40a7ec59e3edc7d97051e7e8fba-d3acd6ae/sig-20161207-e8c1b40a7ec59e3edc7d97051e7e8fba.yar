rule sig_20161207_e8c1b40a7ec59e3edc7d97051e7e8fba {
  meta:
    description = "datamaliciousorder - file 20161207_e8c1b40a7ec59e3edc7d97051e7e8fba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2265d5e3d0783342e3c2867248aaae17eb21441640940517e13c1c1d12082106"

  strings:
    $s1 = "var vEUs6 = new Function(\"vKEq6\", '{return vKEq6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSy0 = new Function(\"vKE" ascii
    $s2 = "2 = new Date();vFFz2[\"setUTCFullYear\"](\"2003\");if (vFFz2.getUTCFullYear().toString(10) == \"2003\") {var vKLd9 = vKEq6.split" ascii
    $s3 = "\"); return vKLd9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEUs6 = new Function(\"vKEq6\", '{return vKEq6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSy0 = new Function(\"vKE" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}