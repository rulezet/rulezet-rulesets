rule TTP_XOR_QUAD_CurrentVersionRun_b795 {
  strings:
    $key_b795 = { e4 fa [2] c0 f4 [2] eb d8 [2] c5 fa [2] d1 e1 [2] de fb [2] c0 e6 [2] c2 e7 [2] d9 e1 [2] c5 e6 [2] d9 c9 }

  condition:
    any of them
}