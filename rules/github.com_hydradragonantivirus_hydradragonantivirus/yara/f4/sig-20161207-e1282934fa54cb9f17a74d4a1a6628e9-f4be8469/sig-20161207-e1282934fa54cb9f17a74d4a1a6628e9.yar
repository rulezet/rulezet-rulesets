rule sig_20161207_e1282934fa54cb9f17a74d4a1a6628e9 {
  meta:
    description = "datamaliciousorder - file 20161207_e1282934fa54cb9f17a74d4a1a6628e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fffe2ee8da3c1b05d19a0787edb3847abfa44a1ef3cab44e614345052d917265"

  strings:
    $s1 = " new Date();vLm7[\"setUTCFullYear\"](\"2003\");if (vLm7.getUTCFullYear().toString(10) == \"2003\") {var vXEt4 = vPd9.split(\"###" ascii
    $s2 = "var vKZd0 = new Function(\"vPd9\", '{return vPd9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJZh4 = new Function(\"vPd9" ascii
    $s3 = "turn vXEt4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKZd0 = new Function(\"vPd9\", '{return vPd9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJZh4 = new Function(\"vPd9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}