rule sig_20161208_d37b89f37a0156b9973ae667c3215ccf {
  meta:
    description = "datamaliciousorder - file 20161208_d37b89f37a0156b9973ae667c3215ccf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd020af5c0bcee170879f1db13493107cb862ff283127e1af3b32957f0d0a5b7"

  strings:
    $s1 = "new Date();vASl4[\"setUTC\"+\"FullYear\"](\"2003\");if (vASl4.getUTCFullYear().toString(10) == \"2003\") {var vEb2 = vMj9.split(" ascii
    $s2 = "var vNi1 = new Function(\"vMj9\", '{return vMj9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVr8 = new Function(\"vMj9\"" ascii
    $s3 = "var vNi1 = new Function(\"vMj9\", '{return vMj9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVr8 = new Function(\"vMj9\"" ascii
    $s4 = " return vEb2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}