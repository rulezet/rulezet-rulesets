rule TTP_XOR_QUAD_CurrentVersionRun_3fd4 {
  strings:
    $key_3fd4 = { 6c bb [2] 48 b5 [2] 63 99 [2] 4d bb [2] 59 a0 [2] 56 ba [2] 48 a7 [2] 4a a6 [2] 51 a0 [2] 4d a7 [2] 51 88 }

  condition:
    any of them
}