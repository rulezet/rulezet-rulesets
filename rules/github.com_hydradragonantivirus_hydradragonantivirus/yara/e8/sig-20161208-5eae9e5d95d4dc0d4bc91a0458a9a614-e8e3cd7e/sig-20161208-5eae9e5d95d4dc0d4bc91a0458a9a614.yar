rule sig_20161208_5eae9e5d95d4dc0d4bc91a0458a9a614 {
  meta:
    description = "datamaliciousorder - file 20161208_5eae9e5d95d4dc0d4bc91a0458a9a614.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18ef2a2ddb90712425b7b812efeb3cd9873e9f72cfdaa7f82d821773d27fefa9"

  strings:
    $s1 = " = new Date();vGt0[\"setUTC\"+\"FullYear\"](\"2003\");if (vGt0.getUTCFullYear().toString(10) == \"2003\") {var vQXi5 = vZUw5.spl" ascii
    $s2 = "var vKZz1 = new Function(\"vZUw5\", '{return vZUw5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJu3 = new Function(\"vZU" ascii
    $s3 = "\"); return vQXi5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKZz1 = new Function(\"vZUw5\", '{return vZUw5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJu3 = new Function(\"vZU" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}