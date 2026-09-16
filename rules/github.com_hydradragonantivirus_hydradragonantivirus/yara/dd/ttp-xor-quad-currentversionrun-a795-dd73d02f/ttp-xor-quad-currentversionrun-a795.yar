rule TTP_XOR_QUAD_CurrentVersionRun_a795 {
  strings:
    $key_a795 = { f4 fa [2] d0 f4 [2] fb d8 [2] d5 fa [2] c1 e1 [2] ce fb [2] d0 e6 [2] d2 e7 [2] c9 e1 [2] d5 e6 [2] c9 c9 }

  condition:
    any of them
}