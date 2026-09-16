rule sig_20161208_057888880a66fc64e58d1321e8faf221 {
  meta:
    description = "datamaliciousorder - file 20161208_057888880a66fc64e58d1321e8faf221.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28e2bbea88c0a7a122548cf24395fe5cd87aec21eddd42ea15203ee39a08baac"

  strings:
    $s1 = " new Date();vFZg6[\"setUTC\"+\"FullYear\"](\"2003\");if (vFZg6.getUTCFullYear().toString(10) == \"2003\") {var vJCu1 = vZi1.spli" ascii
    $s2 = "var vUJz3 = new Function(\"vZi1\", '{return vZi1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUh0 = new Function(\"vZi1" ascii
    $s3 = "); return vJCu1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUJz3 = new Function(\"vZi1\", '{return vZi1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUh0 = new Function(\"vZi1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}