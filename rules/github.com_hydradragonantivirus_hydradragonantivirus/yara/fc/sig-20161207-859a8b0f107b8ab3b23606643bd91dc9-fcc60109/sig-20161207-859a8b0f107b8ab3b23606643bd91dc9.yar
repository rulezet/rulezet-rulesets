rule sig_20161207_859a8b0f107b8ab3b23606643bd91dc9 {
  meta:
    description = "datamaliciousorder - file 20161207_859a8b0f107b8ab3b23606643bd91dc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8ada921b6fbf2c54d0bc2a7cf463e74213bebac06b37668f6932b6de18532a5"

  strings:
    $s1 = "var vFFv0 = new Function(\"vDf4\", '{return vDf4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPn8 = new Function(\"vDf4" ascii
    $s2 = "new Date();vEa9[\"setUTCFullYear\"](\"2003\");if (vEa9.getUTCFullYear().toString(10) == \"2003\") {var vZGa4 = vDf4.split(\"####" ascii
    $s3 = "var vFFv0 = new Function(\"vDf4\", '{return vDf4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPn8 = new Function(\"vDf4" ascii
    $s4 = "urn vZGa4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}