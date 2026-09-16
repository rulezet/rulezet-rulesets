rule TTP_XOR_QUAD_CurrentVersionRun_fb94 {
  strings:
    $key_fb94 = { a8 fb [2] 8c f5 [2] a7 d9 [2] 89 fb [2] 9d e0 [2] 92 fa [2] 8c e7 [2] 8e e6 [2] 95 e0 [2] 89 e7 [2] 95 c8 }

  condition:
    any of them
}