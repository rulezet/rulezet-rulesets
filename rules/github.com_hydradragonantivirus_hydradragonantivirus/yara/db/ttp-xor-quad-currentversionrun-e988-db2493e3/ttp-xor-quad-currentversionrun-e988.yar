rule TTP_XOR_QUAD_CurrentVersionRun_e988 {
  strings:
    $key_e988 = { ba e7 [2] 9e e9 [2] b5 c5 [2] 9b e7 [2] 8f fc [2] 80 e6 [2] 9e fb [2] 9c fa [2] 87 fc [2] 9b fb [2] 87 d4 }

  condition:
    any of them
}