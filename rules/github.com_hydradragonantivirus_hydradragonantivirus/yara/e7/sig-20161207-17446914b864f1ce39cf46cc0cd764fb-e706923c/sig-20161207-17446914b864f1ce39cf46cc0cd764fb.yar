rule sig_20161207_17446914b864f1ce39cf46cc0cd764fb {
  meta:
    description = "datamaliciousorder - file 20161207_17446914b864f1ce39cf46cc0cd764fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f58026b40a444a6da359b696a3caa34239b8dfdeae5e2403dd938d857d6a1333"

  strings:
    $s1 = "0 = new Date();vUXr0[\"setUTCFullYear\"](\"2003\");if (vUXr0.getUTCFullYear().toString(10) == \"2003\") {var vKv4 = vTQh5.split(" ascii
    $s2 = "var vUHa0 = new Function(\"vTQh5\", '{return vTQh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHf6 = new Function(\"vTQ" ascii
    $s3 = "); return vKv4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUHa0 = new Function(\"vTQh5\", '{return vTQh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHf6 = new Function(\"vTQ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}