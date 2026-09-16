rule sig_20161207_05d4e215f30d1c2fda0d6b991231e072 {
  meta:
    description = "datamaliciousorder - file 20161207_05d4e215f30d1c2fda0d6b991231e072.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd4328b3c2963f1a44406db45b65d56a65f32a375e57449e227ecaac0c453109"

  strings:
    $s1 = " = new Date();vMb6[\"setUTCFullYear\"](\"2003\");if (vMb6.getUTCFullYear().toString(10) == \"2003\") {var vOUl3 = vTBa1.split(\"" ascii
    $s2 = "var vFRj1 = new Function(\"vTBa1\", '{return vTBa1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLw6 = new Function(\"vTB" ascii
    $s3 = "var vFRj1 = new Function(\"vTBa1\", '{return vTBa1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLw6 = new Function(\"vTB" ascii
    $s4 = " return vOUl3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}