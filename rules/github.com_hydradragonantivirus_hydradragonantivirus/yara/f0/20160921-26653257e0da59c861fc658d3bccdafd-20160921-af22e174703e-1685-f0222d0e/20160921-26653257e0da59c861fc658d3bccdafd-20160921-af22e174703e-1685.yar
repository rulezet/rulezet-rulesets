rule _20160921_26653257e0da59c861fc658d3bccdafd_20160921_af22e174703e_1685 {
  meta:
    description = "datamaliciousorder - from files 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_af22e174703ebae0fa1368fd471dba37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash2       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"

  strings:
    $s1  = "n fuck(){return \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MO" ascii
    $s2  = "){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})" ascii
    $s3  = " \"Ug\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(func" ascii
    $s4  = "return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(" ascii
    $s5  = ";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function f" ascii
    $s6  = "tion fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retur" ascii
    $s7  = "ion fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s8  = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuc" ascii
    $s9  = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(function fu" ascii
    $s10 = "turn \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s11 = "n \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}