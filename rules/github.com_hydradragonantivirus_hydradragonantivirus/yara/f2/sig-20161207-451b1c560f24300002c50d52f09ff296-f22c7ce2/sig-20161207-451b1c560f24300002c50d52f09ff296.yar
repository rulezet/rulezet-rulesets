rule sig_20161207_451b1c560f24300002c50d52f09ff296 {
  meta:
    description = "datamaliciousorder - file 20161207_451b1c560f24300002c50d52f09ff296.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b0529063c363d65e4d638b2c52d87882fd8df0467995970805138e7c98655c"

  strings:
    $s1 = "var vUMt4 = new Function(\"vMv1\", '{return vMv1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYr8 = new Function(\"vMv1" ascii
    $s2 = " new Date();vVQa5[\"setUTCFullYear\"](\"2003\");if (vVQa5.getUTCFullYear().toString(10) == \"2003\") {var vPb9 = vMv1.split(\"##" ascii
    $s3 = "var vUMt4 = new Function(\"vMv1\", '{return vMv1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYr8 = new Function(\"vMv1" ascii
    $s4 = "eturn vPb9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}