rule TTP_XOR_QUAD_CurrentVersionRun_0b88 {
  strings:
    $key_0b88 = { 58 e7 [2] 7c e9 [2] 57 c5 [2] 79 e7 [2] 6d fc [2] 62 e6 [2] 7c fb [2] 7e fa [2] 65 fc [2] 79 fb [2] 65 d4 }

  condition:
    any of them
}