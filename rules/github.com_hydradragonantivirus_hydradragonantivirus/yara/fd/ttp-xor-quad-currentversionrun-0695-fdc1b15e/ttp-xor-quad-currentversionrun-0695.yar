rule TTP_XOR_QUAD_CurrentVersionRun_0695 {
  strings:
    $key_0695 = { 55 fa [2] 71 f4 [2] 5a d8 [2] 74 fa [2] 60 e1 [2] 6f fb [2] 71 e6 [2] 73 e7 [2] 68 e1 [2] 74 e6 [2] 68 c9 }

  condition:
    any of them
}