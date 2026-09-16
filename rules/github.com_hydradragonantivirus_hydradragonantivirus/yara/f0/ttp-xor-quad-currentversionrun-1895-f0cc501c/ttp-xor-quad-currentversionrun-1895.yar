rule TTP_XOR_QUAD_CurrentVersionRun_1895 {
  strings:
    $key_1895 = { 4b fa [2] 6f f4 [2] 44 d8 [2] 6a fa [2] 7e e1 [2] 71 fb [2] 6f e6 [2] 6d e7 [2] 76 e1 [2] 6a e6 [2] 76 c9 }

  condition:
    any of them
}