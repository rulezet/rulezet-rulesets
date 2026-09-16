rule sig_20161208_e06e3ce17d2b48680bcd73414571b825 {
  meta:
    description = "datamaliciousorder - file 20161208_e06e3ce17d2b48680bcd73414571b825.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4404154b4f7b32c9e92719160730c96f464cb644e0df1a1f44ab2464e57a992"

  strings:
    $s1 = " = new Date();vEg1[\"setUTC\"+\"FullYear\"](\"2003\");if (vEg1.getUTCFullYear().toString(10) == \"2003\") {var vSe4 = vKZt6.spli" ascii
    $s2 = "var vJFn7 = new Function(\"vKZt6\", '{return vKZt6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRw7 = new Function(\"vKZ" ascii
    $s3 = "); return vSe4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vJFn7 = new Function(\"vKZt6\", '{return vKZt6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRw7 = new Function(\"vKZ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}