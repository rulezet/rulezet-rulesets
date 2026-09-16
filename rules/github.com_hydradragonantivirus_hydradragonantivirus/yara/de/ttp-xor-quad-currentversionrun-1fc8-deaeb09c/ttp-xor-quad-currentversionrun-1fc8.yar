rule TTP_XOR_QUAD_CurrentVersionRun_1fc8 {
  strings:
    $key_1fc8 = { 4c a7 [2] 68 a9 [2] 43 85 [2] 6d a7 [2] 79 bc [2] 76 a6 [2] 68 bb [2] 6a ba [2] 71 bc [2] 6d bb [2] 71 94 }

  condition:
    any of them
}