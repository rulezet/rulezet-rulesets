rule TTP_XOR_QUAD_CurrentVersionRun_1689 {
  strings:
    $key_1689 = { 45 e6 [2] 61 e8 [2] 4a c4 [2] 64 e6 [2] 70 fd [2] 7f e7 [2] 61 fa [2] 63 fb [2] 78 fd [2] 64 fa [2] 78 d5 }

  condition:
    any of them
}