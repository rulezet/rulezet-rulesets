rule TTP_XOR_QUAD_CurrentVersionRun_6ad4 {
  strings:
    $key_6ad4 = { 39 bb [2] 1d b5 [2] 36 99 [2] 18 bb [2] 0c a0 [2] 03 ba [2] 1d a7 [2] 1f a6 [2] 04 a0 [2] 18 a7 [2] 04 88 }

  condition:
    any of them
}