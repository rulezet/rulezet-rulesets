rule sig_20161208_dae81e0df2c0429d097ca33334647096 {
  meta:
    description = "datamaliciousorder - file 20161208_dae81e0df2c0429d097ca33334647096.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6fc90f1518052c066a4939e10d51f4a3c9d3d044fc8c2fcd712234c041e0918"

  strings:
    $s1 = "var vDi4 = new Function(\"vFe3\", '{return vFe3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLSh3 = new Function(\"vFe3" ascii
    $s2 = "new Date();vXk4[\"setUTC\"+\"FullYear\"](\"2003\");if (vXk4.getUTCFullYear().toString(10) == \"2003\") {var vOy3 = vFe3.split(\"" ascii
    $s3 = "eturn vOy3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vDi4 = new Function(\"vFe3\", '{return vFe3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLSh3 = new Function(\"vFe3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}