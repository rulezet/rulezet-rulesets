rule sig_20161207_c5ab3df9e498563d295ca69cf42c4698 {
  meta:
    description = "datamaliciousorder - file 20161207_c5ab3df9e498563d295ca69cf42c4698.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b0da5c750c25005faeb716e2cad70440871c97702d47231ff5d5c86871edb96"

  strings:
    $s1 = "var vTh5 = new Function(\"vBi8\", '{var vWr0 = new Date();vWr0[\"setUTCFullYear\"](\"2003\");if (vWr0.getUTCFullYear().toString(" ascii
    $s2 = "var vTh5 = new Function(\"vBi8\", '{var vWr0 = new Date();vWr0[\"setUTCFullYear\"](\"2003\");if (vWr0.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vXr5 = vBi8.split(\"###\"); return vXr5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBx3 = new Function(\"vBi8\", '{return vBi8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}