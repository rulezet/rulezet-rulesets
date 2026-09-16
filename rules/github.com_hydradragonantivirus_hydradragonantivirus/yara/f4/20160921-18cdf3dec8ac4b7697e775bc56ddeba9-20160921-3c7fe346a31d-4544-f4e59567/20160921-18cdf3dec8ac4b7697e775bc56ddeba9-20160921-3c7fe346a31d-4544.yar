rule _20160921_18cdf3dec8ac4b7697e775bc56ddeba9_20160921_3c7fe346a31d_4544 {
  meta:
    description = "datamaliciousorder - from files 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js, 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"
    hash2       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash3       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash4       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1 = "ction f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s2 = ";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f0" ascii
    $s3 = "n \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s4 = "function f000(){return \"Tb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){re" ascii
    $s5 = "return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}