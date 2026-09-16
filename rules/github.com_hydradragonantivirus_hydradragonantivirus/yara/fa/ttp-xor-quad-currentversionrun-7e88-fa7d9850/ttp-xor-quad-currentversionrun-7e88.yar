rule TTP_XOR_QUAD_CurrentVersionRun_7e88 {
  strings:
    $key_7e88 = { 2d e7 [2] 09 e9 [2] 22 c5 [2] 0c e7 [2] 18 fc [2] 17 e6 [2] 09 fb [2] 0b fa [2] 10 fc [2] 0c fb [2] 10 d4 }

  condition:
    any of them
}