rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_8dce9d2aa0d1_4971 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_d7a1651fca7129364bbe9da7195a89dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash3       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"
    hash4       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash5       = "2c37b7e410e05a2e285f2d4909012cdefffdcc0d9e06b06aafce7aba5b9684f6"

  strings:
    $s1 = "(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){ret" ascii
    $s2 = "g\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3 = "eturn \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(" ascii
    $s4 = "ction fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s5 = " fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}