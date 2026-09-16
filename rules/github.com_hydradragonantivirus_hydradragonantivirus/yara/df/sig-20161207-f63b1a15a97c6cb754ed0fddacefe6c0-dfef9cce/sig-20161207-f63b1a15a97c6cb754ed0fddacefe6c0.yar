rule sig_20161207_f63b1a15a97c6cb754ed0fddacefe6c0 {
  meta:
    description = "datamaliciousorder - file 20161207_f63b1a15a97c6cb754ed0fddacefe6c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa49ccb7313aaa738ecf76e93d6fa20f58025a8bb504ae46d637c125ad656376"

  strings:
    $s1 = "var vELq6 = new Function(\"vSe1\", '{return vSe1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPp2 = new Function(\"vSe1" ascii
    $s2 = " new Date();vOOg9[\"setUTCFullYear\"](\"2003\");if (vOOg9.getUTCFullYear().toString(10) == \"2003\") {var vMj3 = vSe1.split(\"##" ascii
    $s3 = "eturn vMj3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vELq6 = new Function(\"vSe1\", '{return vSe1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPp2 = new Function(\"vSe1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}