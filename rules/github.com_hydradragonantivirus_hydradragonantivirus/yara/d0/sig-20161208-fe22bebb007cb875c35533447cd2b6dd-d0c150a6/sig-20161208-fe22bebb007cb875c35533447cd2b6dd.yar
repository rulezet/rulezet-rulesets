rule sig_20161208_fe22bebb007cb875c35533447cd2b6dd {
  meta:
    description = "datamaliciousorder - file 20161208_fe22bebb007cb875c35533447cd2b6dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988dded23b9216e15c1a1542af20d9bf9b250ed1b26af0e5c615c7c1657b22d8"

  strings:
    $s1 = " = new Date();vXd4[\"setUTC\"+\"FullYear\"](\"2003\");if (vXd4.getUTCFullYear().toString(10) == \"2003\") {var vWy8 = vKGf0.spli" ascii
    $s2 = "var vLTj6 = new Function(\"vKGf0\", '{return vKGf0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFi3 = new Function(\"vKG" ascii
    $s3 = "var vLTj6 = new Function(\"vKGf0\", '{return vKGf0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFi3 = new Function(\"vKG" ascii
    $s4 = "); return vWy8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}