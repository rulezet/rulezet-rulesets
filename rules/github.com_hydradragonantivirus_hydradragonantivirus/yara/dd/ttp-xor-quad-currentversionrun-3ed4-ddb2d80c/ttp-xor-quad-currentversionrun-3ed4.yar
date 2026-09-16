rule TTP_XOR_QUAD_CurrentVersionRun_3ed4 {
  strings:
    $key_3ed4 = { 6d bb [2] 49 b5 [2] 62 99 [2] 4c bb [2] 58 a0 [2] 57 ba [2] 49 a7 [2] 4b a6 [2] 50 a0 [2] 4c a7 [2] 50 88 }

  condition:
    any of them
}