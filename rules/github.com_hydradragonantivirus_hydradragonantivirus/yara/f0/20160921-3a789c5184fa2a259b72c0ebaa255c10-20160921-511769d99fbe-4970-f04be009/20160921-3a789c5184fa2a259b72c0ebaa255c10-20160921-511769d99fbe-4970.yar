rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_511769d99fbe_4970 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash3       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash4       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash5       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"
    hash6       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"
    hash7       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1 = " \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s2 = "fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"S" ascii
    $s3 = "{return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";}" ascii
    $s4 = "return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(" ascii
    $s5 = "\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}