rule sig_20161208_54219e2010547c9d791138e023b2c41b {
  meta:
    description = "datamaliciousorder - file 20161208_54219e2010547c9d791138e023b2c41b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e2e1142f2913779476503951d50949de64c96adaaa32ee4d4d3db89f3b3ce6f"

  strings:
    $s1 = "new Date();vNy1[\"setUTC\"+\"FullYear\"](\"2003\");if (vNy1.getUTCFullYear().toString(10) == \"2003\") {var vBw7 = vMa2.split(\"" ascii
    $s2 = "var vSx7 = new Function(\"vMa2\", '{return vMa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIEk2 = new Function(\"vMa2" ascii
    $s3 = "eturn vBw7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSx7 = new Function(\"vMa2\", '{return vMa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIEk2 = new Function(\"vMa2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}