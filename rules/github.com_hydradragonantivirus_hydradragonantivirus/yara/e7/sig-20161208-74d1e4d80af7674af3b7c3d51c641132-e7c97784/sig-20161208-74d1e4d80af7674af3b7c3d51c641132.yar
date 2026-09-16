rule sig_20161208_74d1e4d80af7674af3b7c3d51c641132 {
  meta:
    description = "datamaliciousorder - file 20161208_74d1e4d80af7674af3b7c3d51c641132.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3713cadf0d51cd124d18e6c2e117b8a0362519f48f833188ae9432adf303b605"

  strings:
    $s1 = "var vVh7 = new Function(\"vWNf3\", '{return vWNf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTBy4 = new Function(\"vWN" ascii
    $s2 = "8 = new Date();vFBe8[\"setUTC\"+\"FullYear\"](\"2003\");if (vFBe8.getUTCFullYear().toString(10) == \"2003\") {var vXj5 = vWNf3.s" ascii
    $s3 = "var vVh7 = new Function(\"vWNf3\", '{return vWNf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTBy4 = new Function(\"vWN" ascii
    $s4 = "##\"); return vXj5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}