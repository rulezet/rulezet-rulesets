rule TTP_XOR_QUAD_CurrentVersionRun_fa95 {
  strings:
    $key_fa95 = { a9 fa [2] 8d f4 [2] a6 d8 [2] 88 fa [2] 9c e1 [2] 93 fb [2] 8d e6 [2] 8f e7 [2] 94 e1 [2] 88 e6 [2] 94 c9 }

  condition:
    any of them
}