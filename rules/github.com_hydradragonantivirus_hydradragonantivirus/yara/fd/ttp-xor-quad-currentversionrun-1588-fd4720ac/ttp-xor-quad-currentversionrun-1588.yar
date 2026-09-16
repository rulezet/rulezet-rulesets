rule TTP_XOR_QUAD_CurrentVersionRun_1588 {
  strings:
    $key_1588 = { 46 e7 [2] 62 e9 [2] 49 c5 [2] 67 e7 [2] 73 fc [2] 7c e6 [2] 62 fb [2] 60 fa [2] 7b fc [2] 67 fb [2] 7b d4 }

  condition:
    any of them
}