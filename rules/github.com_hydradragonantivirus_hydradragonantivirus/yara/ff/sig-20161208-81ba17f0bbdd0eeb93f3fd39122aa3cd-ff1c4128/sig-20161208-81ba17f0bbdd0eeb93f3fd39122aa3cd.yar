rule sig_20161208_81ba17f0bbdd0eeb93f3fd39122aa3cd {
  meta:
    description = "datamaliciousorder - file 20161208_81ba17f0bbdd0eeb93f3fd39122aa3cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ff1799901e69910c2121358e8fac5eadb73c0e18e6f45a6db7da6286f9210ff"

  strings:
    $s1 = "ew Date();vWq5[\"setUTC\"+\"FullYear\"](\"2003\");if (vWq5.getUTCFullYear().toString(10) == \"2003\") {var vMSr7 = vMi2.split(\"" ascii
    $s2 = "var vTu4 = new Function(\"vMi2\", '{return vMi2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLb7 = new Function(\"vMi2\"" ascii
    $s3 = "eturn vMSr7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTu4 = new Function(\"vMi2\", '{return vMi2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLb7 = new Function(\"vMi2\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}