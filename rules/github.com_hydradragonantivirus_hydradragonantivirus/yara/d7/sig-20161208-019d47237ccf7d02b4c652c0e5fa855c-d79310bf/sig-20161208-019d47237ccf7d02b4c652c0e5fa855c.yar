rule sig_20161208_019d47237ccf7d02b4c652c0e5fa855c {
  meta:
    description = "datamaliciousorder - file 20161208_019d47237ccf7d02b4c652c0e5fa855c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58f3f9f6553af62117589306dad09282f7cb06a7aa7b92abd77d24179994a716"

  strings:
    $s1 = "var vTz8 = new Function(\"vMj2\", '{return vMj2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEPq6 = new Function(\"vMj2" ascii
    $s2 = "new Date();vPs4[\"setUTC\"+\"FullYear\"](\"2003\");if (vPs4.getUTCFullYear().toString(10) == \"2003\") {var vSGk9 = vMj2.split(" ascii
    $s3 = "return vSGk9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTz8 = new Function(\"vMj2\", '{return vMj2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEPq6 = new Function(\"vMj2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}