rule TTP_XOR_QUAD_CurrentVersionRun_3b88 {
  strings:
    $key_3b88 = { 68 e7 [2] 4c e9 [2] 67 c5 [2] 49 e7 [2] 5d fc [2] 52 e6 [2] 4c fb [2] 4e fa [2] 55 fc [2] 49 fb [2] 55 d4 }

  condition:
    any of them
}