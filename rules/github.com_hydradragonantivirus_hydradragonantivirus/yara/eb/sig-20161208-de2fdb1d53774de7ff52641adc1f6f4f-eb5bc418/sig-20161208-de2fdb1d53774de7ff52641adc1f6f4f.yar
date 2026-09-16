rule sig_20161208_de2fdb1d53774de7ff52641adc1f6f4f {
  meta:
    description = "datamaliciousorder - file 20161208_de2fdb1d53774de7ff52641adc1f6f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61bb8f70affc7d5ee7ceb5d3f1786535213ee05f8a3773a5893413142430d712"

  strings:
    $s1 = "= new Date();vMVv7[\"setUTC\"+\"FullYear\"](\"2003\");if (vMVv7.getUTCFullYear().toString(10) == \"2003\") {var vMy7 = vIl7.spli" ascii
    $s2 = "var vGRq3 = new Function(\"vIl7\", '{return vIl7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOBk2 = new Function(\"vIl7" ascii
    $s3 = "var vGRq3 = new Function(\"vIl7\", '{return vIl7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOBk2 = new Function(\"vIl7" ascii
    $s4 = "); return vMy7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}