rule TTP_XOR_QUAD_CurrentVersionRun_7088 {
  strings:
    $key_7088 = { 23 e7 [2] 07 e9 [2] 2c c5 [2] 02 e7 [2] 16 fc [2] 19 e6 [2] 07 fb [2] 05 fa [2] 1e fc [2] 02 fb [2] 1e d4 }

  condition:
    any of them
}