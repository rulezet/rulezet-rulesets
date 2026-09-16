rule sig_20161207_fc1a5a19118738704bb6ca34df815c7b {
  meta:
    description = "datamaliciousorder - file 20161207_fc1a5a19118738704bb6ca34df815c7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4075baf824ee0fa11cc4980d65364b0911cca718aefb1f89ac0f9f5e0a852d1"

  strings:
    $s1 = "var vEb0 = new Function(\"vBi9\", '{return vBi9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDg6 = new Function(\"vBi9\"" ascii
    $s2 = "ew Date();vJi5[\"setUTCFullYear\"](\"2003\");if (vJi5.getUTCFullYear().toString(10) == \"2003\") {var vZh1 = vBi9.split(\"####\"" ascii
    $s3 = "var vEb0 = new Function(\"vBi9\", '{return vBi9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDg6 = new Function(\"vBi9\"" ascii
    $s4 = "n vZh1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}