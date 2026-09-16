rule TTP_XOR_QUAD_CurrentVersionRun_0ed4 {
  strings:
    $key_0ed4 = { 5d bb [2] 79 b5 [2] 52 99 [2] 7c bb [2] 68 a0 [2] 67 ba [2] 79 a7 [2] 7b a6 [2] 60 a0 [2] 7c a7 [2] 60 88 }

  condition:
    any of them
}