rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_27fb26e7e153_4281 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = ";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s2 = "n\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function" ascii
    $s3 = " f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu" ascii
    $s4 = "0(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";}" ascii
    $s5 = "\"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}