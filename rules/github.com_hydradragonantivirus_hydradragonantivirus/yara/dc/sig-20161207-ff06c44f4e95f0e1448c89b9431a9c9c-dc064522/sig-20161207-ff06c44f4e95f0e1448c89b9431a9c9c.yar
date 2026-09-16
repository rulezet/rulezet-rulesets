rule sig_20161207_ff06c44f4e95f0e1448c89b9431a9c9c {
  meta:
    description = "datamaliciousorder - file 20161207_ff06c44f4e95f0e1448c89b9431a9c9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01315cb0194a4d5f42eb808fa037747bd34f67ad82c29e83d6306affba26210b"

  strings:
    $s1 = "4 = new Date();vUNe4[\"setUTCFullYear\"](\"2003\");if (vUNe4.getUTCFullYear().toString(10) == \"2003\") {var vEDx6 = vEQy2.split" ascii
    $s2 = "var vIYv5 = new Function(\"vEQy2\", '{return vEQy2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFp5 = new Function(\"vEQ" ascii
    $s3 = "\"); return vEDx6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vIYv5 = new Function(\"vEQy2\", '{return vEQy2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFp5 = new Function(\"vEQ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}