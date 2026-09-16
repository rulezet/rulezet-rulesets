rule TTP_XOR_QUAD_CurrentVersionRun_c086 {
  strings:
    $key_c086 = { 93 e9 [2] b7 e7 [2] 9c cb [2] b2 e9 [2] a6 f2 [2] a9 e8 [2] b7 f5 [2] b5 f4 [2] ae f2 [2] b2 f5 [2] ae da }

  condition:
    any of them
}