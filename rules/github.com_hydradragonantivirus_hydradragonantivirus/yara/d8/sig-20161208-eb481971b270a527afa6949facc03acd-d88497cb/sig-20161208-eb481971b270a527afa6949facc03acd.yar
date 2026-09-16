rule sig_20161208_eb481971b270a527afa6949facc03acd {
  meta:
    description = "datamaliciousorder - file 20161208_eb481971b270a527afa6949facc03acd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ca61266689cf22385cdb6943af001888b92fd588680ad73e5de2022182e647d"

  strings:
    $s1 = "new Date();vEi4[\"setUTC\"+\"FullYear\"](\"2003\");if (vEi4.getUTCFullYear().toString(10) == \"2003\") {var vYRd5 = vTf1.split(" ascii
    $s2 = "var vRx0 = new Function(\"vTf1\", '{return vTf1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFPb1 = new Function(\"vTf1" ascii
    $s3 = "return vYRd5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRx0 = new Function(\"vTf1\", '{return vTf1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFPb1 = new Function(\"vTf1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}