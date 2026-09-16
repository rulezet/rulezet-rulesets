rule sig_20161207_91d2ac1c632247e0d715f4020da9effe {
  meta:
    description = "datamaliciousorder - file 20161207_91d2ac1c632247e0d715f4020da9effe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b87ec062e4e2634900c5865b31c91c8596baafd7a661633405ddac2567eff0df"

  strings:
    $s1 = "var vFx9 = new Function(\"vGWb5\", '{return vGWb5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIq6 = new Function(\"vGWb" ascii
    $s2 = "= new Date();vKt1[\"setUTCFullYear\"](\"2003\");if (vKt1.getUTCFullYear().toString(10) == \"2003\") {var vIe2 = vGWb5.split(\"##" ascii
    $s3 = "var vFx9 = new Function(\"vGWb5\", '{return vGWb5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIq6 = new Function(\"vGWb" ascii
    $s4 = "eturn vIe2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}