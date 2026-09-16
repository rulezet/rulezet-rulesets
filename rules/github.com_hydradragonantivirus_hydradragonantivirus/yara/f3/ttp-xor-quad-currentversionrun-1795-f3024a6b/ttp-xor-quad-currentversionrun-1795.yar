rule TTP_XOR_QUAD_CurrentVersionRun_1795 {
  strings:
    $key_1795 = { 44 fa [2] 60 f4 [2] 4b d8 [2] 65 fa [2] 71 e1 [2] 7e fb [2] 60 e6 [2] 62 e7 [2] 79 e1 [2] 65 e6 [2] 79 c9 }

  condition:
    any of them
}