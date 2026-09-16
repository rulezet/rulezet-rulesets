rule sig_20161208_e1581552757a154ffd5d728be6b27ebd {
  meta:
    description = "datamaliciousorder - file 20161208_e1581552757a154ffd5d728be6b27ebd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6973043c11ba20a39898ac115a53d2f554dd9d075beee2ab6d9e69393985012d"

  strings:
    $s1 = "ew Date();vYs4[\"setUTC\"+\"FullYear\"](\"2003\");if (vYs4.getUTCFullYear().toString(10) == \"2003\") {var vSv0 = vNu3.split(\"#" ascii
    $s2 = "var vQy0 = new Function(\"vNu3\", '{return vNu3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCr0 = new Function(\"vNu3\"" ascii
    $s3 = "var vQy0 = new Function(\"vNu3\", '{return vNu3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCr0 = new Function(\"vNu3\"" ascii
    $s4 = "turn vSv0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}