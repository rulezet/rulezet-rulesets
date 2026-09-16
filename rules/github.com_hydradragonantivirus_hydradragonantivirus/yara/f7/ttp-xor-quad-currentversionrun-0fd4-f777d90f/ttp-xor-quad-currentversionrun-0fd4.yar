rule TTP_XOR_QUAD_CurrentVersionRun_0fd4 {
  strings:
    $key_0fd4 = { 5c bb [2] 78 b5 [2] 53 99 [2] 7d bb [2] 69 a0 [2] 66 ba [2] 78 a7 [2] 7a a6 [2] 61 a0 [2] 7d a7 [2] 61 88 }

  condition:
    any of them
}