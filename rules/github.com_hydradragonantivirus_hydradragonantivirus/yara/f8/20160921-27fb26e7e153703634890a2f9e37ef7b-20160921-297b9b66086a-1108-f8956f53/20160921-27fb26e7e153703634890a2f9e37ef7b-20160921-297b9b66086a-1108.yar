rule _20160921_27fb26e7e153703634890a2f9e37ef7b_20160921_297b9b66086a_1108 {
  meta:
    description = "datamaliciousorder - from files 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash2       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash3       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash4       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1  = "0(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"KDh\"" ascii
    $s2  = "000(){return \"MMz\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb" ascii
    $s3  = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(function " ascii
    $s4  = "(){return \"Yv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";}" ascii
    $s5  = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MMz\";})(),(function f000" ascii
    $s6  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s7  = ",(function f000(){return \"Wb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s8  = "on f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s9  = "0(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TRc" ascii
    $s10 = "(function f000(){return \"ZFe\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){" ascii
    $s11 = "unction f000(){return \"NBs\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s12 = "return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(" ascii
    $s13 = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Nx\";})(),(function f" ascii
    $s14 = "\"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s15 = "urn \"Mt\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(f" ascii
    $s16 = "return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\";})()" ascii
    $s17 = "on f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}