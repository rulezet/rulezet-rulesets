rule sig_20161207_dd65248bf1a4418dd4285eddd4ea2c98 {
  meta:
    description = "datamaliciousorder - file 20161207_dd65248bf1a4418dd4285eddd4ea2c98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12297545b4ba88d09131a70248c94114b398cb2614d58e43bd26f099d1f1f084"

  strings:
    $s1 = "4 = new Date();vXQv4[\"setUTCFullYear\"](\"2003\");if (vXQv4.getUTCFullYear().toString(10) == \"2003\") {var vQVy8 = vOJn5.split" ascii
    $s2 = "var vJj0 = new Function(\"vOJn5\", '{return vOJn5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLb50 = new Function(\"vOJ" ascii
    $s3 = "var vJj0 = new Function(\"vOJn5\", '{return vOJn5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLb50 = new Function(\"vOJ" ascii
    $s4 = "\"); return vQVy8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}