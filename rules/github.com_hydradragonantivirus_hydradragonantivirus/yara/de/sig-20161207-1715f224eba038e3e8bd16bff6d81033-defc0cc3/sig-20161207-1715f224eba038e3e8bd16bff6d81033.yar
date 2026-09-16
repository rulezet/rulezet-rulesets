rule sig_20161207_1715f224eba038e3e8bd16bff6d81033 {
  meta:
    description = "datamaliciousorder - file 20161207_1715f224eba038e3e8bd16bff6d81033.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a52a0dd05dbea0ddbae7f7156dad934539fb094849fb0a2f3327e7c5f579a179"

  strings:
    $s1 = "var vUb0 = new Function(\"vKKb2\", '{return vKKb2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDx3 = new Function(\"vKKb" ascii
    $s2 = "= new Date();vIg6[\"setUTCFullYear\"](\"2003\");if (vIg6.getUTCFullYear().toString(10) == \"2003\") {var vEc8 = vKKb2.split(\"##" ascii
    $s3 = "eturn vEc8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUb0 = new Function(\"vKKb2\", '{return vKKb2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDx3 = new Function(\"vKKb" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}