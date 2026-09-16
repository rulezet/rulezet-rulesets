rule TTP_XOR_QUAD_CurrentVersionRun_f489 {
  strings:
    $key_f489 = { a7 e6 [2] 83 e8 [2] a8 c4 [2] 86 e6 [2] 92 fd [2] 9d e7 [2] 83 fa [2] 81 fb [2] 9a fd [2] 86 fa [2] 9a d5 }

  condition:
    any of them
}