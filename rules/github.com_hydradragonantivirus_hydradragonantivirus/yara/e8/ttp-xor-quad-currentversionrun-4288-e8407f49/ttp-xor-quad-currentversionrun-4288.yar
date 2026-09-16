rule TTP_XOR_QUAD_CurrentVersionRun_4288 {
  strings:
    $key_4288 = { 11 e7 [2] 35 e9 [2] 1e c5 [2] 30 e7 [2] 24 fc [2] 2b e6 [2] 35 fb [2] 37 fa [2] 2c fc [2] 30 fb [2] 2c d4 }

  condition:
    any of them
}