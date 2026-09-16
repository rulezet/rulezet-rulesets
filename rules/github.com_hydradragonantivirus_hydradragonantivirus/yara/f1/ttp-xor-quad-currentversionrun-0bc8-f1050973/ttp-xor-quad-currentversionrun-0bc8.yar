rule TTP_XOR_QUAD_CurrentVersionRun_0bc8 {
  strings:
    $key_0bc8 = { 58 a7 [2] 7c a9 [2] 57 85 [2] 79 a7 [2] 6d bc [2] 62 a6 [2] 7c bb [2] 7e ba [2] 65 bc [2] 79 bb [2] 65 94 }

  condition:
    any of them
}