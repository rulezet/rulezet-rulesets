rule sig_20161208_819941a36f133247ed200c97300aa159 {
  meta:
    description = "datamaliciousorder - file 20161208_819941a36f133247ed200c97300aa159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa09c151ac442667c40230294c01a598a98f9dc0ed3650347ddab0e19276fd3b"

  strings:
    $s1 = "new Date();vMDe9[\"setUTC\"+\"FullYear\"](\"2003\");if (vMDe9.getUTCFullYear().toString(10) == \"2003\") {var vPNr3 = vJm0.split" ascii
    $s2 = "var vSn6 = new Function(\"vJm0\", '{return vJm0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCc6 = new Function(\"vJm0\"" ascii
    $s3 = "; return vPNr3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSn6 = new Function(\"vJm0\", '{return vJm0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCc6 = new Function(\"vJm0\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}