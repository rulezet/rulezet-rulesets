rule TTP_XOR_QUAD_CurrentVersionRun_01d4 {
  strings:
    $key_01d4 = { 52 bb [2] 76 b5 [2] 5d 99 [2] 73 bb [2] 67 a0 [2] 68 ba [2] 76 a7 [2] 74 a6 [2] 6f a0 [2] 73 a7 [2] 6f 88 }

  condition:
    any of them
}