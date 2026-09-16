rule TTP_XOR_QUAD_CurrentVersionRun_6288 {
  strings:
    $key_6288 = { 31 e7 [2] 15 e9 [2] 3e c5 [2] 10 e7 [2] 04 fc [2] 0b e6 [2] 15 fb [2] 17 fa [2] 0c fc [2] 10 fb [2] 0c d4 }

  condition:
    any of them
}