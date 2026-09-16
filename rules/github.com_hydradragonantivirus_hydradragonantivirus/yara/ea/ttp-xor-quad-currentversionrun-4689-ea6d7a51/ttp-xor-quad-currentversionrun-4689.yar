rule TTP_XOR_QUAD_CurrentVersionRun_4689 {
  strings:
    $key_4689 = { 15 e6 [2] 31 e8 [2] 1a c4 [2] 34 e6 [2] 20 fd [2] 2f e7 [2] 31 fa [2] 33 fb [2] 28 fd [2] 34 fa [2] 28 d5 }

  condition:
    any of them
}