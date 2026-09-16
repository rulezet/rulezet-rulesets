rule _20160822_030625a12b63f9d1d74b9bb94c4e7f79_20160901_b1d42cc96883_4099 {
  meta:
    description = "datamaliciousorder - from files 20160822_030625a12b63f9d1d74b9bb94c4e7f79.js, 20160901_b1d42cc96883d71e5d8d12d924c2fcff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8172a5345e393364ee04be1c94e8c9cf04dcc1a164cf016bce236bbd7db29eb"
    hash2       = "e4a45d2ccb385b2bc3474541a818caa740a68cc278a0f6ac42eaf23429465d2e"

  strings:
    $s1 = "function kl() {" fullword ascii
    $s2 = "return G;" fullword ascii
    $s3 = "function B() {" fullword ascii
    $s4 = "function y() {" fullword ascii
    $s5 = "return EJ;" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}