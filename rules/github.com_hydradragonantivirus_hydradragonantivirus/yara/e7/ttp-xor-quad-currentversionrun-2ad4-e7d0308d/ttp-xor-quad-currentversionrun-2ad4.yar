rule TTP_XOR_QUAD_CurrentVersionRun_2ad4 {
  strings:
    $key_2ad4 = { 79 bb [2] 5d b5 [2] 76 99 [2] 58 bb [2] 4c a0 [2] 43 ba [2] 5d a7 [2] 5f a6 [2] 44 a0 [2] 58 a7 [2] 44 88 }

  condition:
    any of them
}