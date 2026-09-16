rule TTP_XOR_QUAD_CurrentVersionRun_de88 {
  strings:
    $key_de88 = { 8d e7 [2] a9 e9 [2] 82 c5 [2] ac e7 [2] b8 fc [2] b7 e6 [2] a9 fb [2] ab fa [2] b0 fc [2] ac fb [2] b0 d4 }

  condition:
    any of them
}