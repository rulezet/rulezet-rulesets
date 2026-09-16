rule sig_20161207_2bef663c7db17f52a9a49c07f9da4d28 {
  meta:
    description = "datamaliciousorder - file 20161207_2bef663c7db17f52a9a49c07f9da4d28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6d97034be50423211c828e52ced2127f731b8b1f01ea6af3963fb9ddcb32ba7"

  strings:
    $s1 = "var vDp4 = new Function(\"vVi8\", '{return vVi8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVFy1 = new Function(\"vVi8" ascii
    $s2 = " new Date();vPPf8[\"setUTCFullYear\"](\"2003\");if (vPPf8.getUTCFullYear().toString(10) == \"2003\") {var vXOy4 = vVi8.split(\"#" ascii
    $s3 = "var vDp4 = new Function(\"vVi8\", '{return vVi8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVFy1 = new Function(\"vVi8" ascii
    $s4 = "return vXOy4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}