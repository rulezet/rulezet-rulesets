rule TTP_XOR_QUAD_CurrentVersionRun_e4d6 {
  strings:
    $key_e4d6 = { b7 b9 [2] 93 b7 [2] b8 9b [2] 96 b9 [2] 82 a2 [2] 8d b8 [2] 93 a5 [2] 91 a4 [2] 8a a2 [2] 96 a5 [2] 8a 8a }

  condition:
    any of them
}