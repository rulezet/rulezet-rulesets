rule sig_20161207_31f2eb7efe8aa36965b6440a2730dadf {
  meta:
    description = "datamaliciousorder - file 20161207_31f2eb7efe8aa36965b6440a2730dadf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ca4bdffa7d24c783d9baedec75747d03b420d265423a01270fc8475a8e512ef"

  strings:
    $s1 = "var vKi7 = new Function(\"vYQb1\", '{return vYQb1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVn1 = new Function(\"vYQb" ascii
    $s2 = "= new Date();vIs0[\"setUTCFullYear\"](\"2003\");if (vIs0.getUTCFullYear().toString(10) == \"2003\") {var vBl8 = vYQb1.split(\"##" ascii
    $s3 = "eturn vBl8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKi7 = new Function(\"vYQb1\", '{return vYQb1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVn1 = new Function(\"vYQb" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}