rule sig_20161208_e61387e97c723ff6454195fc4cd2480d {
  meta:
    description = "datamaliciousorder - file 20161208_e61387e97c723ff6454195fc4cd2480d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cf1dac1fa7426e3d19545edabd7594efa0020c3f890cf7936c614f0a92a1f2b"

  strings:
    $s1 = " new Date();vRMk7[\"setUTC\"+\"FullYear\"](\"2003\");if (vRMk7.getUTCFullYear().toString(10) == \"2003\") {var vHEz5 = vZo4.spli" ascii
    $s2 = "var vCRr2 = new Function(\"vZo4\", '{return vZo4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEy0 = new Function(\"vZo4" ascii
    $s3 = "var vCRr2 = new Function(\"vZo4\", '{return vZo4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEy0 = new Function(\"vZo4" ascii
    $s4 = "); return vHEz5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}