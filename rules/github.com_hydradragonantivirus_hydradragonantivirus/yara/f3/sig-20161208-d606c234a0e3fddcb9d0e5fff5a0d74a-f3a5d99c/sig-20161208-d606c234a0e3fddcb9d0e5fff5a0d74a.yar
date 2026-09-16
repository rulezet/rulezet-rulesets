rule sig_20161208_d606c234a0e3fddcb9d0e5fff5a0d74a {
  meta:
    description = "datamaliciousorder - file 20161208_d606c234a0e3fddcb9d0e5fff5a0d74a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7749cd447d7bb4a3b7ba468316cf3fd8a071f76cd58b6eceb5988bb9e3bd4ac"

  strings:
    $s1 = "var vIAa4 = new Function(\"vFn5\", '{return vFn5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJh6 = new Function(\"vFn5" ascii
    $s2 = "new Date();vVp5[\"setUTC\"+\"FullYear\"](\"2003\");if (vVp5.getUTCFullYear().toString(10) == \"2003\") {var vBUm5 = vFn5.split(" ascii
    $s3 = "return vBUm5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vIAa4 = new Function(\"vFn5\", '{return vFn5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJh6 = new Function(\"vFn5" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}