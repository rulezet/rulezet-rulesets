rule TTP_XOR_QUAD_CurrentVersionRun_3795 {
  strings:
    $key_3795 = { 64 fa [2] 40 f4 [2] 6b d8 [2] 45 fa [2] 51 e1 [2] 5e fb [2] 40 e6 [2] 42 e7 [2] 59 e1 [2] 45 e6 [2] 59 c9 }

  condition:
    any of them
}