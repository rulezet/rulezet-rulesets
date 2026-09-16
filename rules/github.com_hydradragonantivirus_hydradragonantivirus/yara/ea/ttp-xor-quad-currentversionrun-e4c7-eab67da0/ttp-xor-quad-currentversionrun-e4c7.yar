rule TTP_XOR_QUAD_CurrentVersionRun_e4c7 {
  strings:
    $key_e4c7 = { b7 a8 [2] 93 a6 [2] b8 8a [2] 96 a8 [2] 82 b3 [2] 8d a9 [2] 93 b4 [2] 91 b5 [2] 8a b3 [2] 96 b4 [2] 8a 9b }

  condition:
    any of them
}