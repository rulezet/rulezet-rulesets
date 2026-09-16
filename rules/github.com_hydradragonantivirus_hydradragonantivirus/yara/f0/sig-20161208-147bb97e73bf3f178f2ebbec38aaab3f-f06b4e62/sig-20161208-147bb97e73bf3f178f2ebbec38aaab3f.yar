rule sig_20161208_147bb97e73bf3f178f2ebbec38aaab3f {
  meta:
    description = "datamaliciousorder - file 20161208_147bb97e73bf3f178f2ebbec38aaab3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af93eb2f05202088293cbf74d52e81045c18332414d569629bb4208e795d5c79"

  strings:
    $s1 = "6 = new Date();vKu6[\"setUTC\"+\"FullYear\"](\"2003\");if (vKu6.getUTCFullYear().toString(10) == \"2003\") {var vQf8 = vDFg0.spl" ascii
    $s2 = "var vOFh5 = new Function(\"vDFg0\", '{return vDFg0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQAl7 = new Function(\"vD" ascii
    $s3 = "\"); return vQf8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vOFh5 = new Function(\"vDFg0\", '{return vDFg0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQAl7 = new Function(\"vD" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}