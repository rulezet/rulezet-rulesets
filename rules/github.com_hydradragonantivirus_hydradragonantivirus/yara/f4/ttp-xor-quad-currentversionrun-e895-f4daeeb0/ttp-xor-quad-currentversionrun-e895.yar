rule TTP_XOR_QUAD_CurrentVersionRun_e895 {
  strings:
    $key_e895 = { bb fa [2] 9f f4 [2] b4 d8 [2] 9a fa [2] 8e e1 [2] 81 fb [2] 9f e6 [2] 9d e7 [2] 86 e1 [2] 9a e6 [2] 86 c9 }

  condition:
    any of them
}