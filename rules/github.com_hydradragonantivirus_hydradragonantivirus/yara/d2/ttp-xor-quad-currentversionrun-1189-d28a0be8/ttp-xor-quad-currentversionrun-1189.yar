rule TTP_XOR_QUAD_CurrentVersionRun_1189 {
  strings:
    $key_1189 = { 42 e6 [2] 66 e8 [2] 4d c4 [2] 63 e6 [2] 77 fd [2] 78 e7 [2] 66 fa [2] 64 fb [2] 7f fd [2] 63 fa [2] 7f d5 }

  condition:
    any of them
}