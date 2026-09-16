rule _20160822_030625a12b63f9d1d74b9bb94c4e7f79_20160822_50bfd50b89fc_941 {
  meta:
    description = "datamaliciousorder - from files 20160822_030625a12b63f9d1d74b9bb94c4e7f79.js, 20160822_50bfd50b89fc45d60bbc30ddc2bcc7cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8172a5345e393364ee04be1c94e8c9cf04dcc1a164cf016bce236bbd7db29eb"
    hash2       = "ddb3299e4f5792b9ec2f22028a018195c32bfc82783e730c61b6a5e4a4c84d4d"

  strings:
    $s1 = "function R() {" fullword ascii
    $s2 = "function X() {" fullword ascii
    $s3 = "return jb;" fullword ascii
    $s4 = "function I() {" fullword ascii
    $s5 = "return M;" fullword ascii
    $s6 = "return na;" fullword ascii
    $s7 = "return A;" fullword ascii
    $s8 = "return zN;" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}