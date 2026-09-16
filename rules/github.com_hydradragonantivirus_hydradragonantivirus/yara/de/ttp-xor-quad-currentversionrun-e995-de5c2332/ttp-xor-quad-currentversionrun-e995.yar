rule TTP_XOR_QUAD_CurrentVersionRun_e995 {
  strings:
    $key_e995 = { ba fa [2] 9e f4 [2] b5 d8 [2] 9b fa [2] 8f e1 [2] 80 fb [2] 9e e6 [2] 9c e7 [2] 87 e1 [2] 9b e6 [2] 87 c9 }

  condition:
    any of them
}