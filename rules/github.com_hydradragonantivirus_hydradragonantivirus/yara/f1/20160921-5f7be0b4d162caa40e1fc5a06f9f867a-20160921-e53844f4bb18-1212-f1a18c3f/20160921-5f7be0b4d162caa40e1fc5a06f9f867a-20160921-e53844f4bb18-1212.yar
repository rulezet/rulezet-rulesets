rule _20160921_5f7be0b4d162caa40e1fc5a06f9f867a_20160921_e53844f4bb18_1212 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash2       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1  = "g\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"DAa\";})(),(function" ascii
    $s2  = "on fuck(){return \"LGo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"" ascii
    $s4  = "urn \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"KVh\";})(),(" ascii
    $s5  = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){ret" ascii
    $s6  = "w\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function " ascii
    $s7  = " \"DAa\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo\";})(),(fun" ascii
    $s8  = "rn \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(fu" ascii
    $s9  = "ction fuck(){return \"Ai\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s10 = "return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Wo0\";})" ascii
    $s11 = "eturn \"DRx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})()" ascii
    $s12 = "unction fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){ret" ascii
    $s13 = " fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"" ascii
    $s14 = ")(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck" ascii
    $s15 = "ck(){return \"UXf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s16 = "(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}