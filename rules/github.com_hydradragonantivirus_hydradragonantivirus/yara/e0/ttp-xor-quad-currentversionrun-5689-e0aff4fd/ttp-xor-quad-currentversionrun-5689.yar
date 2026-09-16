rule TTP_XOR_QUAD_CurrentVersionRun_5689 {
  strings:
    $key_5689 = { 05 e6 [2] 21 e8 [2] 0a c4 [2] 24 e6 [2] 30 fd [2] 3f e7 [2] 21 fa [2] 23 fb [2] 38 fd [2] 24 fa [2] 38 d5 }

  condition:
    any of them
}