rule TTP_XOR_QUAD_CurrentVersionRun_5e88 {
  strings:
    $key_5e88 = { 0d e7 [2] 29 e9 [2] 02 c5 [2] 2c e7 [2] 38 fc [2] 37 e6 [2] 29 fb [2] 2b fa [2] 30 fc [2] 2c fb [2] 30 d4 }

  condition:
    any of them
}