rule TTP_XOR_QUAD_CurrentVersionRun_4bc8 {
  strings:
    $key_4bc8 = { 18 a7 [2] 3c a9 [2] 17 85 [2] 39 a7 [2] 2d bc [2] 22 a6 [2] 3c bb [2] 3e ba [2] 25 bc [2] 39 bb [2] 25 94 }

  condition:
    any of them
}