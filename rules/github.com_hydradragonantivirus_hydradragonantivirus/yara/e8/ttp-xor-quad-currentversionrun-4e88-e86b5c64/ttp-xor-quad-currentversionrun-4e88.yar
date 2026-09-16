rule TTP_XOR_QUAD_CurrentVersionRun_4e88 {
  strings:
    $key_4e88 = { 1d e7 [2] 39 e9 [2] 12 c5 [2] 3c e7 [2] 28 fc [2] 27 e6 [2] 39 fb [2] 3b fa [2] 20 fc [2] 3c fb [2] 20 d4 }

  condition:
    any of them
}