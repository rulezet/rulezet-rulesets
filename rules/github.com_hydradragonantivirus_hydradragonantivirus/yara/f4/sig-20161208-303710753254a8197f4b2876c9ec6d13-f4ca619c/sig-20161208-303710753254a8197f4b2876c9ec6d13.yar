rule sig_20161208_303710753254a8197f4b2876c9ec6d13 {
  meta:
    description = "datamaliciousorder - file 20161208_303710753254a8197f4b2876c9ec6d13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c047b97ed19b64401be5d282ac8c795c07c20ac5ab967ca073e0be5622c1dc"

  strings:
    $s1 = "new Date();vBQu9[\"setUTC\"+\"FullYear\"](\"2003\");if (vBQu9.getUTCFullYear().toString(10) == \"2003\") {var vSFy7 = vGe3.split" ascii
    $s2 = "var vUj4 = new Function(\"vGe3\", '{return vGe3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWb2 = new Function(\"vGe3\"" ascii
    $s3 = "var vUj4 = new Function(\"vGe3\", '{return vGe3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWb2 = new Function(\"vGe3\"" ascii
    $s4 = "; return vSFy7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}