rule sig_20161207_87f4f8b7ee80988228bc375a9bfdb132 {
  meta:
    description = "datamaliciousorder - file 20161207_87f4f8b7ee80988228bc375a9bfdb132.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26643cc22841b6f7134e244746e438f14975a572fdb7711a9b354cb9c403e233"

  strings:
    $s1 = "var vFVr7 = new Function(\"vSp8\", '{return vSp8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSBv9 = new Function(\"vSp8" ascii
    $s2 = " new Date();vAm2[\"setUTCFullYear\"](\"2003\");if (vAm2.getUTCFullYear().toString(10) == \"2003\") {var vLt6 = vSp8.split(\"####" ascii
    $s3 = "var vFVr7 = new Function(\"vSp8\", '{return vSp8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSBv9 = new Function(\"vSp8" ascii
    $s4 = "urn vLt6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}