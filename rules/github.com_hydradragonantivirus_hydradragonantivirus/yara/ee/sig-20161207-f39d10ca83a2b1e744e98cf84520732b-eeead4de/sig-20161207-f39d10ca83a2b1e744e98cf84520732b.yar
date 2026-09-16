rule sig_20161207_f39d10ca83a2b1e744e98cf84520732b {
  meta:
    description = "datamaliciousorder - file 20161207_f39d10ca83a2b1e744e98cf84520732b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70d2e68c627d6e6aa389daf76ed41de62087761ff9939a54c783020622762a7c"

  strings:
    $s1 = "var vEd4 = new Function(\"vYNa1\", '{return vYNa1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWz3 = new Function(\"vYNa" ascii
    $s2 = "= new Date();vEs1[\"setUTCFullYear\"](\"2003\");if (vEs1.getUTCFullYear().toString(10) == \"2003\") {var vVd1 = vYNa1.split(\"##" ascii
    $s3 = "var vEd4 = new Function(\"vYNa1\", '{return vYNa1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWz3 = new Function(\"vYNa" ascii
    $s4 = "eturn vVd1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}