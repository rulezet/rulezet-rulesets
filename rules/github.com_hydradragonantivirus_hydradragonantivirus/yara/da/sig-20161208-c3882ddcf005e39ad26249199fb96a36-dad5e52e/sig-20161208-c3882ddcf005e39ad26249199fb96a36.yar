rule sig_20161208_c3882ddcf005e39ad26249199fb96a36 {
  meta:
    description = "datamaliciousorder - file 20161208_c3882ddcf005e39ad26249199fb96a36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dd1fdaa6977dd286b4c9093f0b28fea8021774b697d5c58a0fe3e651ef48b93"

  strings:
    $s1 = " new Date();vLg7[\"setUTC\"+\"FullYear\"](\"2003\");if (vLg7.getUTCFullYear().toString(10) == \"2003\") {var vNf3 = vKv1.split(" ascii
    $s2 = "var vNQw4 = new Function(\"vKv1\", '{return vKv1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJZe4 = new Function(\"vKv1" ascii
    $s3 = "return vNf3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNQw4 = new Function(\"vKv1\", '{return vKv1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJZe4 = new Function(\"vKv1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}