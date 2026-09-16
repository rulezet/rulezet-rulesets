rule TTP_XOR_QUAD_CurrentVersionRun_6bc8 {
  strings:
    $key_6bc8 = { 38 a7 [2] 1c a9 [2] 37 85 [2] 19 a7 [2] 0d bc [2] 02 a6 [2] 1c bb [2] 1e ba [2] 05 bc [2] 19 bb [2] 05 94 }

  condition:
    any of them
}