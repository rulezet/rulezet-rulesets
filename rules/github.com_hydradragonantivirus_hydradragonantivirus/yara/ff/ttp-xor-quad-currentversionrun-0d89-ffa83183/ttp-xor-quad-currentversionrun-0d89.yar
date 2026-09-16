rule TTP_XOR_QUAD_CurrentVersionRun_0d89 {
  strings:
    $key_0d89 = { 5e e6 [2] 7a e8 [2] 51 c4 [2] 7f e6 [2] 6b fd [2] 64 e7 [2] 7a fa [2] 78 fb [2] 63 fd [2] 7f fa [2] 63 d5 }

  condition:
    any of them
}