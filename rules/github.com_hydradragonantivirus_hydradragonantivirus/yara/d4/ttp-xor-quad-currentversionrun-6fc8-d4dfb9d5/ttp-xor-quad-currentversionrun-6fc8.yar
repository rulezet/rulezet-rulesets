rule TTP_XOR_QUAD_CurrentVersionRun_6fc8 {
  strings:
    $key_6fc8 = { 3c a7 [2] 18 a9 [2] 33 85 [2] 1d a7 [2] 09 bc [2] 06 a6 [2] 18 bb [2] 1a ba [2] 01 bc [2] 1d bb [2] 01 94 }

  condition:
    any of them
}