rule sig_20161207_bd88c41225eab61b2e95cd4f09760ee2 {
  meta:
    description = "datamaliciousorder - file 20161207_bd88c41225eab61b2e95cd4f09760ee2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99997aca02884bfc99f81c0aa92bef39ccf173788a662ff567f057d774dc0849"

  strings:
    $s1 = "ew Date();vPm3[\"setUTCFullYear\"](\"2003\");if (vPm3.getUTCFullYear().toString(10) == \"2003\") {var vFj9 = vTx8.split(\"####\"" ascii
    $s2 = "var vRr0 = new Function(\"vTx8\", '{return vTx8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLs0 = new Function(\"vTx8\"" ascii
    $s3 = "n vFj9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRr0 = new Function(\"vTx8\", '{return vTx8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLs0 = new Function(\"vTx8\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}