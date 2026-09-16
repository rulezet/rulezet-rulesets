rule TTP_XOR_QUAD_CurrentVersionRun_3ad4 {
  strings:
    $key_3ad4 = { 69 bb [2] 4d b5 [2] 66 99 [2] 48 bb [2] 5c a0 [2] 53 ba [2] 4d a7 [2] 4f a6 [2] 54 a0 [2] 48 a7 [2] 54 88 }

  condition:
    any of them
}