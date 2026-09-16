rule TTP_XOR_QUAD_CurrentVersionRun_1f88 {
  strings:
    $key_1f88 = { 4c e7 [2] 68 e9 [2] 43 c5 [2] 6d e7 [2] 79 fc [2] 76 e6 [2] 68 fb [2] 6a fa [2] 71 fc [2] 6d fb [2] 71 d4 }

  condition:
    any of them
}