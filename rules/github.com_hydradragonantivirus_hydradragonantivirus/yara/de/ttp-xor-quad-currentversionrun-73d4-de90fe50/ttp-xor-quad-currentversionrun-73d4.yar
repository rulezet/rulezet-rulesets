rule TTP_XOR_QUAD_CurrentVersionRun_73d4 {
  strings:
    $key_73d4 = { 20 bb [2] 04 b5 [2] 2f 99 [2] 01 bb [2] 15 a0 [2] 1a ba [2] 04 a7 [2] 06 a6 [2] 1d a0 [2] 01 a7 [2] 1d 88 }

  condition:
    any of them
}