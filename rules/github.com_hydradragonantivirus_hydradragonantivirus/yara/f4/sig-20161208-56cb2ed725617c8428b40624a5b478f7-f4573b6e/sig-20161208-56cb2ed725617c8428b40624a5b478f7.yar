rule sig_20161208_56cb2ed725617c8428b40624a5b478f7 {
  meta:
    description = "datamaliciousorder - file 20161208_56cb2ed725617c8428b40624a5b478f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f09991a5cc62ad3bb683a6f45dd1acc66ab779bb69fd6e5a710d6dba49ca838e"

  strings:
    $s1 = "var vTe6 = new Function(\"vHOf1\", '{return vHOf1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSEb7 = new Function(\"vHO" ascii
    $s2 = "5 = new Date();vICz5[\"setUTC\"+\"FullYear\"](\"2003\");if (vICz5.getUTCFullYear().toString(10) == \"2003\") {var vNa0 = vHOf1.s" ascii
    $s3 = "##\"); return vNa0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTe6 = new Function(\"vHOf1\", '{return vHOf1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSEb7 = new Function(\"vHO" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}