rule sig_20161207_5c74129c8cbecff5c2b1bfe3ad5d0974 {
  meta:
    description = "datamaliciousorder - file 20161207_5c74129c8cbecff5c2b1bfe3ad5d0974.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5b252ec206597dcfdf9a3a08b4f884760518b2c1975bc2c94923b75288dc140"

  strings:
    $s1 = "9 = new Date();vYOo9[\"setUTCFullYear\"](\"2003\");if (vYOo9.getUTCFullYear().toString(10) == \"2003\") {var vNp2 = vSWl7.split(" ascii
    $s2 = "var vYa6 = new Function(\"vSWl7\", '{return vSWl7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAIk4 = new Function(\"vSW" ascii
    $s3 = "); return vNp2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYa6 = new Function(\"vSWl7\", '{return vSWl7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAIk4 = new Function(\"vSW" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}