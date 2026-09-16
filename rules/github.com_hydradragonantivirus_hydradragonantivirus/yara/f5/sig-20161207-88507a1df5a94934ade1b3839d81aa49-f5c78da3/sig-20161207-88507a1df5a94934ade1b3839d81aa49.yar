rule sig_20161207_88507a1df5a94934ade1b3839d81aa49 {
  meta:
    description = "datamaliciousorder - file 20161207_88507a1df5a94934ade1b3839d81aa49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f24835b4e7158b7318e259846d33ea78f664aff65b2f0c4c5d6f8414d469fe42"

  strings:
    $s1 = "var vXv7 = new Function(\"vMm9\", '{var vTf7 = new Date();vTf7[\"setUTCFullYear\"](\"2003\");if (vTf7.getUTCFullYear().toString(" ascii
    $s2 = "var vXv7 = new Function(\"vMm9\", '{var vTf7 = new Date();vTf7[\"setUTCFullYear\"](\"2003\");if (vTf7.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vPh5 = vMm9.split(\"###\"); return vPh5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWc3 = new Function(\"vMm9\", '{return vMm9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}