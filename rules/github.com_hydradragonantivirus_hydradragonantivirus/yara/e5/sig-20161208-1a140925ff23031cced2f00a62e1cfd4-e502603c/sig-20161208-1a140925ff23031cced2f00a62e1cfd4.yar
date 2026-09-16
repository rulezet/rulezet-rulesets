rule sig_20161208_1a140925ff23031cced2f00a62e1cfd4 {
  meta:
    description = "datamaliciousorder - file 20161208_1a140925ff23031cced2f00a62e1cfd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2dd4ea29e749edc33511471fcb9fa915c948febbe40e25ef0e8810fa8d88b35"

  strings:
    $s1 = "var vWr4 = new Function(\"vBXz8\", '{return vBXz8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEg5 = new Function(\"vBXz" ascii
    $s2 = "= new Date();vEp6[\"setUTC\"+\"FullYear\"](\"2003\");if (vEp6.getUTCFullYear().toString(10) == \"2003\") {var vGr2 = vBXz8.split" ascii
    $s3 = "; return vGr2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWr4 = new Function(\"vBXz8\", '{return vBXz8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEg5 = new Function(\"vBXz" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}