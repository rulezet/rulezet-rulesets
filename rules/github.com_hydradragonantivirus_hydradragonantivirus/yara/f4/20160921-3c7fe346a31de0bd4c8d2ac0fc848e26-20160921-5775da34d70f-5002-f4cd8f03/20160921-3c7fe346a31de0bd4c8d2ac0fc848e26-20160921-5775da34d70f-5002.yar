rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_5775da34d70f_5002 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash3       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash4       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1 = "{return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(" ascii
    $s2 = "turn \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return" ascii
    $s4 = "00(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";" ascii
    $s5 = "){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}