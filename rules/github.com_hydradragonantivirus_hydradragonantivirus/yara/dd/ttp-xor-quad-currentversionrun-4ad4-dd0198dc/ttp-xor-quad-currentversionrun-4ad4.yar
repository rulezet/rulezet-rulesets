rule TTP_XOR_QUAD_CurrentVersionRun_4ad4 {
  strings:
    $key_4ad4 = { 19 bb [2] 3d b5 [2] 16 99 [2] 38 bb [2] 2c a0 [2] 23 ba [2] 3d a7 [2] 3f a6 [2] 24 a0 [2] 38 a7 [2] 24 88 }

  condition:
    any of them
}