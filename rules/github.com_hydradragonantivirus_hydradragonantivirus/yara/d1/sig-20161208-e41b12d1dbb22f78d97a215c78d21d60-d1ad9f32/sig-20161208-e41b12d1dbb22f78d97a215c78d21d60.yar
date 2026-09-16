rule sig_20161208_e41b12d1dbb22f78d97a215c78d21d60 {
  meta:
    description = "datamaliciousorder - file 20161208_e41b12d1dbb22f78d97a215c78d21d60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d91cef5e4b700219881fbd045ae2d40dc1e63a43691474ca326b460d8e426200"

  strings:
    $s1 = "new Date();vSZh5[\"setUTC\"+\"FullYear\"](\"2003\");if (vSZh5.getUTCFullYear().toString(10) == \"2003\") {var vCAb0 = vBr2.split" ascii
    $s2 = "var vMw4 = new Function(\"vBr2\", '{return vBr2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWl8 = new Function(\"vBr2\"" ascii
    $s3 = "var vMw4 = new Function(\"vBr2\", '{return vBr2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWl8 = new Function(\"vBr2\"" ascii
    $s4 = "; return vCAb0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}