rule sig_20161208_aac7a8910c754e19f0d852e41170c44e {
  meta:
    description = "datamaliciousorder - file 20161208_aac7a8910c754e19f0d852e41170c44e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1ac0f1fb73de6ebca250447f13a09c3305f30f8144b268eafb5a274971b9d2e"

  strings:
    $s1 = "var vZZu1 = new Function(\"vYc0\", '{return vYc0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNh3 = new Function(\"vYc0" ascii
    $s2 = "new Date();vKx3[\"setUTC\"+\"FullYear\"](\"2003\");if (vKx3.getUTCFullYear().toString(10) == \"2003\") {var vFQy2 = vYc0.split(" ascii
    $s3 = "var vZZu1 = new Function(\"vYc0\", '{return vYc0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNh3 = new Function(\"vYc0" ascii
    $s4 = "return vFQy2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}