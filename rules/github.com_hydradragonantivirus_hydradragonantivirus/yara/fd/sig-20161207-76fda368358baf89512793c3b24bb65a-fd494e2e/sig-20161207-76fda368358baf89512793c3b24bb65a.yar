rule sig_20161207_76fda368358baf89512793c3b24bb65a {
  meta:
    description = "datamaliciousorder - file 20161207_76fda368358baf89512793c3b24bb65a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "886f9787fd6855eb92f431921004f5da4f87b444a446696f988319ae34d4c60f"

  strings:
    $s1 = "var vBYd7 = new Function(\"vMLm6\", '{var vYUe0 = new Date();vYUe0[\"setUTCFullYear\"](\"2003\");if (vYUe0.getUTCFullYear().toSt" ascii
    $s2 = "var vBYd7 = new Function(\"vMLm6\", '{var vYUe0 = new Date();vYUe0[\"setUTCFullYear\"](\"2003\");if (vYUe0.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vQLi1 = vMLm6.split(\"###\"); return vQLi1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vJr6 = new Function(\"vMLm6\", '{return vMLm6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}