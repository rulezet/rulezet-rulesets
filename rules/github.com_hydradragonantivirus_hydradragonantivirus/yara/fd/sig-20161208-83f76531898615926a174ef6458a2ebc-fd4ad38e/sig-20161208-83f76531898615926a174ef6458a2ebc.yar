rule sig_20161208_83f76531898615926a174ef6458a2ebc {
  meta:
    description = "datamaliciousorder - file 20161208_83f76531898615926a174ef6458a2ebc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91816f2674dc53d04c32cebda9678ecf3f98e59ccc3cca369a6d568fbc3706a0"

  strings:
    $s1 = "var vQFt7 = new Function(\"vXAo8\", '{return vXAo8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGQl8 = new Function(\"vX" ascii
    $s2 = "1 = new Date();vWh1[\"setUTC\"+\"FullYear\"](\"2003\");if (vWh1.getUTCFullYear().toString(10) == \"2003\") {var vUTt4 = vXAo8.sp" ascii
    $s3 = "var vQFt7 = new Function(\"vXAo8\", '{return vXAo8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGQl8 = new Function(\"vX" ascii
    $s4 = "#\"); return vUTt4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}