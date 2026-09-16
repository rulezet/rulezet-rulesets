rule TTP_XOR_QUAD_CurrentVersionRun_6b94 {
  strings:
    $key_6b94 = { 38 fb [2] 1c f5 [2] 37 d9 [2] 19 fb [2] 0d e0 [2] 02 fa [2] 1c e7 [2] 1e e6 [2] 05 e0 [2] 19 e7 [2] 05 c8 }

  condition:
    any of them
}