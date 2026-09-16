rule sig_20161208_329a117f3d4c7b817861571ede08abdc {
  meta:
    description = "datamaliciousorder - file 20161208_329a117f3d4c7b817861571ede08abdc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef534b53e53428dab0e8b3b37a5792c0adebf8b4616674efa5b8f12740dc3c6e"

  strings:
    $s1 = "= new Date();vGy1[\"setUTC\"+\"FullYear\"](\"2003\");if (vGy1.getUTCFullYear().toString(10) == \"2003\") {var vRw9 = vYJd4.split" ascii
    $s2 = "var vPo7 = new Function(\"vYJd4\", '{return vYJd4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYl1 = new Function(\"vYJd" ascii
    $s3 = "; return vRw9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPo7 = new Function(\"vYJd4\", '{return vYJd4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYl1 = new Function(\"vYJd" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}