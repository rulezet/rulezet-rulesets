rule sig_20161207_1f9776001772d2f6d3c965b2598d2169 {
  meta:
    description = "datamaliciousorder - file 20161207_1f9776001772d2f6d3c965b2598d2169.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3e9b20f934dfb3c333750c8dca6576ad600b0ef8addeafd692b679d1e434092"

  strings:
    $s1 = "var vWBg6 = new Function(\"vESd7\", '{return vESd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZg4 = new Function(\"vES" ascii
    $s2 = " = new Date();vNc5[\"setUTCFullYear\"](\"2003\");if (vNc5.getUTCFullYear().toString(10) == \"2003\") {var vGv9 = vESd7.split(\"#" ascii
    $s3 = "return vGv9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWBg6 = new Function(\"vESd7\", '{return vESd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZg4 = new Function(\"vES" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}