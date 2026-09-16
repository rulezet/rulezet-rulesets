rule TTP_XOR_QUAD_CurrentVersionRun_5b88 {
  strings:
    $key_5b88 = { 08 e7 [2] 2c e9 [2] 07 c5 [2] 29 e7 [2] 3d fc [2] 32 e6 [2] 2c fb [2] 2e fa [2] 35 fc [2] 29 fb [2] 35 d4 }

  condition:
    any of them
}