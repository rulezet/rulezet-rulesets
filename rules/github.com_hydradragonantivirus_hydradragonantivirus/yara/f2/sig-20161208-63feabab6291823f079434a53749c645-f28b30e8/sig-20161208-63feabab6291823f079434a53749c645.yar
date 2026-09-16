rule sig_20161208_63feabab6291823f079434a53749c645 {
  meta:
    description = "datamaliciousorder - file 20161208_63feabab6291823f079434a53749c645.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1a0751b3ef58012d690df67f6d750bd5f20bbc8a37bb370b2ecb7e48c8acba4"

  strings:
    $s1 = " = new Date();vJv9[\"setUTC\"+\"FullYear\"](\"2003\");if (vJv9.getUTCFullYear().toString(10) == \"2003\") {var vAq3 = vZEm9.spli" ascii
    $s2 = "var vXDc5 = new Function(\"vZEm9\", '{return vZEm9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMr7 = new Function(\"vZE" ascii
    $s3 = "); return vAq3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vXDc5 = new Function(\"vZEm9\", '{return vZEm9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMr7 = new Function(\"vZE" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}