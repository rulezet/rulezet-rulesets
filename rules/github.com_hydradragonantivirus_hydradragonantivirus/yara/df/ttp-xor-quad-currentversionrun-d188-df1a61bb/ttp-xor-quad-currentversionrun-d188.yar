rule TTP_XOR_QUAD_CurrentVersionRun_d188 {
  strings:
    $key_d188 = { 82 e7 [2] a6 e9 [2] 8d c5 [2] a3 e7 [2] b7 fc [2] b8 e6 [2] a6 fb [2] a4 fa [2] bf fc [2] a3 fb [2] bf d4 }

  condition:
    any of them
}