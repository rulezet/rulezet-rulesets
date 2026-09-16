rule sig_20161207_77526133bbb1fdee8721d0ac4707f527 {
  meta:
    description = "datamaliciousorder - file 20161207_77526133bbb1fdee8721d0ac4707f527.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12567e10ed028aa284c5d2df41d02fb6eeeefbc56f92aedd3797b427919cd26c"

  strings:
    $s1 = "var vPFj6 = new Function(\"vPPw9\", '{return vPPw9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRCr4 = new Function(\"vP" ascii
    $s2 = "5 = new Date();vGm5[\"setUTCFullYear\"](\"2003\");if (vGm5.getUTCFullYear().toString(10) == \"2003\") {var vFOw6 = vPPw9.split(" ascii
    $s3 = "; return vFOw6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPFj6 = new Function(\"vPPw9\", '{return vPPw9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRCr4 = new Function(\"vP" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}