rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_582a5b9e6263_3553 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash3       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"

  strings:
    $s1 = "){return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";}" ascii
    $s2 = "eturn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})()" ascii
    $s3 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Km\";})(),(function f00" ascii
    $s4 = "ction f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s5 = "0(){return \"Ml\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";}" ascii
    $s6 = ";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}