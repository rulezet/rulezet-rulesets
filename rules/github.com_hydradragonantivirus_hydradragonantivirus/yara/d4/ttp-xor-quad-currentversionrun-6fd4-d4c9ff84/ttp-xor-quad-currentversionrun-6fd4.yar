rule TTP_XOR_QUAD_CurrentVersionRun_6fd4 {
  strings:
    $key_6fd4 = { 3c bb [2] 18 b5 [2] 33 99 [2] 1d bb [2] 09 a0 [2] 06 ba [2] 18 a7 [2] 1a a6 [2] 01 a0 [2] 1d a7 [2] 01 88 }

  condition:
    any of them
}