rule sig_20161207_d6b11d5bc3df624e13c0b42b1516437b {
  meta:
    description = "datamaliciousorder - file 20161207_d6b11d5bc3df624e13c0b42b1516437b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7da29a82d18a6d4d870df33f24ede8b6c2d82345f97a131f60cc51c097dfbfb2"

  strings:
    $s1 = "var vAi4 = new Function(\"vQFa1\", '{return vQFa1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAZw5 = new Function(\"vQF" ascii
    $s2 = "5 = new Date();vIZi5[\"setUTCFullYear\"](\"2003\");if (vIZi5.getUTCFullYear().toString(10) == \"2003\") {var vZAw1 = vQFa1.split" ascii
    $s3 = "\"); return vZAw1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vAi4 = new Function(\"vQFa1\", '{return vQFa1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAZw5 = new Function(\"vQF" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}