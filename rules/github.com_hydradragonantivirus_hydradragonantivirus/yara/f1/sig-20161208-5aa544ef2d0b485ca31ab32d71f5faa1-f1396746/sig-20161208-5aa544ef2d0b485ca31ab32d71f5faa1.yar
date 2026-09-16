rule sig_20161208_5aa544ef2d0b485ca31ab32d71f5faa1 {
  meta:
    description = "datamaliciousorder - file 20161208_5aa544ef2d0b485ca31ab32d71f5faa1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95de1b860d9538096f22e1c1172c4db91375648b00d8ccc24138b6a2fae3106a"

  strings:
    $s1 = " = new Date();vVm1[\"setUTC\"+\"FullYear\"](\"2003\");if (vVm1.getUTCFullYear().toString(10) == \"2003\") {var vBXw7 = vKIm1.spl" ascii
    $s2 = "var vFEi3 = new Function(\"vKIm1\", '{return vKIm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPz2 = new Function(\"vKI" ascii
    $s3 = "\"); return vBXw7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFEi3 = new Function(\"vKIm1\", '{return vKIm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPz2 = new Function(\"vKI" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}