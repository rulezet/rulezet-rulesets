rule sig_20161207_bfd453f05a227f8db1cb16a153303c7a {
  meta:
    description = "datamaliciousorder - file 20161207_bfd453f05a227f8db1cb16a153303c7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e6140a1582d5ae91808a510311c8f6760d07aec2aef573bca05408252fa2e82"

  strings:
    $s1 = "var vRCf1 = new Function(\"vFJc3\", '{var vMWd5 = new Date();vMWd5[\"setUTCFullYear\"](\"2003\");if (vMWd5.getUTCFullYear().toSt" ascii
    $s2 = "var vRCf1 = new Function(\"vFJc3\", '{var vMWd5 = new Date();vMWd5[\"setUTCFullYear\"](\"2003\");if (vMWd5.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vUHj1 = vFJc3.split(\"###\"); return vUHj1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vOGl4 = new Function(\"vFJc3\", '{return vFJc3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}