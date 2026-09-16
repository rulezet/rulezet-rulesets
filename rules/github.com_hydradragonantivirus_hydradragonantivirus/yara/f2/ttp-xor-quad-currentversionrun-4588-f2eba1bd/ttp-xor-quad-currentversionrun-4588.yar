rule TTP_XOR_QUAD_CurrentVersionRun_4588 {
  strings:
    $key_4588 = { 16 e7 [2] 32 e9 [2] 19 c5 [2] 37 e7 [2] 23 fc [2] 2c e6 [2] 32 fb [2] 30 fa [2] 2b fc [2] 37 fb [2] 2b d4 }

  condition:
    any of them
}