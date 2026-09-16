rule sig_20161207_ee0af642dac24d8bce767c7066c9087a {
  meta:
    description = "datamaliciousorder - file 20161207_ee0af642dac24d8bce767c7066c9087a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27c025c3336b4743b880684da31a8d04a898523810b4fd71b0bf010fd8dbc7d5"

  strings:
    $s1 = " new Date();vUHy6[\"setUTCFullYear\"](\"2003\");if (vUHy6.getUTCFullYear().toString(10) == \"2003\") {var vOBc0 = vHw6.split(\"#" ascii
    $s2 = "var vNy6 = new Function(\"vHw6\", '{return vHw6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKFw7 = new Function(\"vHw6" ascii
    $s3 = "return vOBc0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNy6 = new Function(\"vHw6\", '{return vHw6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKFw7 = new Function(\"vHw6" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}