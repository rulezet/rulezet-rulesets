rule sig_20161208_354c4c03b925cb72f202f816c36223a3 {
  meta:
    description = "datamaliciousorder - file 20161208_354c4c03b925cb72f202f816c36223a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f48e05c307b097fe03bdd1048b3a60b514cb16ad11f074cf12ee4028f5489601"

  strings:
    $s1 = "var vQd3 = new Function(\"vPGl6\", '{return vPGl6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKh5 = new Function(\"vPGl" ascii
    $s2 = "= new Date();vPx1[\"setUTC\"+\"FullYear\"](\"2003\");if (vPx1.getUTCFullYear().toString(10) == \"2003\") {var vUHa5 = vPGl6.spli" ascii
    $s3 = "); return vUHa5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQd3 = new Function(\"vPGl6\", '{return vPGl6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKh5 = new Function(\"vPGl" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}