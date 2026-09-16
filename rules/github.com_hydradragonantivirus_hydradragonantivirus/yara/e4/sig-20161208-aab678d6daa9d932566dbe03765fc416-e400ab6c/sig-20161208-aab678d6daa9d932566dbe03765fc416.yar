rule sig_20161208_aab678d6daa9d932566dbe03765fc416 {
  meta:
    description = "datamaliciousorder - file 20161208_aab678d6daa9d932566dbe03765fc416.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0da2bff3440ed4ca9862ab7a8e17dd99471083a5d58c3f1106c17f5469ad06f7"

  strings:
    $s1 = "var vGTa2 = new Function(\"vEj9\", '{return vEj9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHUq1 = new Function(\"vEj9" ascii
    $s2 = "= new Date();vUQp4[\"setUTC\"+\"FullYear\"](\"2003\");if (vUQp4.getUTCFullYear().toString(10) == \"2003\") {var vHTc6 = vEj9.spl" ascii
    $s3 = "\"); return vHTc6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGTa2 = new Function(\"vEj9\", '{return vEj9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHUq1 = new Function(\"vEj9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}