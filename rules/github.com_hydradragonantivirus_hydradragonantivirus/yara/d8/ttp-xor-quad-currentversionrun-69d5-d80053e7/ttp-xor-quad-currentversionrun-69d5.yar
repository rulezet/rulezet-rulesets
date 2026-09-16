rule TTP_XOR_QUAD_CurrentVersionRun_69d5 {
  strings:
    $key_69d5 = { 3a ba [2] 1e b4 [2] 35 98 [2] 1b ba [2] 0f a1 [2] 00 bb [2] 1e a6 [2] 1c a7 [2] 07 a1 [2] 1b a6 [2] 07 89 }

  condition:
    any of them
}