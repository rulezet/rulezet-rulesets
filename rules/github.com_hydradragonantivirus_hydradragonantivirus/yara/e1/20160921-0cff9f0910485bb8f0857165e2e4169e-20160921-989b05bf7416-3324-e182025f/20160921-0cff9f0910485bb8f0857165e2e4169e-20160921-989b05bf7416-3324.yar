rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_989b05bf7416_3324 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"
    hash5       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "return \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})()" ascii
    $s2 = " f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TK" ascii
    $s3 = ",(function f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){" ascii
    $s4 = "eturn \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(" ascii
    $s5 = "IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s6 = ";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}