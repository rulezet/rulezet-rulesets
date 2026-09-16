rule sig_20161207_9a8952121e7b623ee09eb2cbcb725e0d {
  meta:
    description = "datamaliciousorder - file 20161207_9a8952121e7b623ee09eb2cbcb725e0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3f88b60dae0aeed4264a12d3cfb00cbd3c9297715765cba012bd4f590a5e5d5"

  strings:
    $s1 = " new Date();vOFf0[\"setUTCFullYear\"](\"2003\");if (vOFf0.getUTCFullYear().toString(10) == \"2003\") {var vUz8 = vIn4.split(\"##" ascii
    $s2 = "var vCp5 = new Function(\"vIn4\", '{return vIn4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZNt3 = new Function(\"vIn4" ascii
    $s3 = "eturn vUz8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vCp5 = new Function(\"vIn4\", '{return vIn4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZNt3 = new Function(\"vIn4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}