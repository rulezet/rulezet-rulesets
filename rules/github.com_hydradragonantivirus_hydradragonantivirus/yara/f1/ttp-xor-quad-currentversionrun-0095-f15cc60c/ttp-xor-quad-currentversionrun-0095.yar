rule TTP_XOR_QUAD_CurrentVersionRun_0095 {
  strings:
    $key_0095 = { 53 fa [2] 77 f4 [2] 5c d8 [2] 72 fa [2] 66 e1 [2] 69 fb [2] 77 e6 [2] 75 e7 [2] 6e e1 [2] 72 e6 [2] 6e c9 }

  condition:
    any of them
}