rule TTP_XOR_QUAD_CurrentVersionRun_5288 {
  strings:
    $key_5288 = { 01 e7 [2] 25 e9 [2] 0e c5 [2] 20 e7 [2] 34 fc [2] 3b e6 [2] 25 fb [2] 27 fa [2] 3c fc [2] 20 fb [2] 3c d4 }

  condition:
    any of them
}