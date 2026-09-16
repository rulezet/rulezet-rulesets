rule TTP_XOR_QUAD_CurrentVersionRun_2bc8 {
  strings:
    $key_2bc8 = { 78 a7 [2] 5c a9 [2] 77 85 [2] 59 a7 [2] 4d bc [2] 42 a6 [2] 5c bb [2] 5e ba [2] 45 bc [2] 59 bb [2] 45 94 }

  condition:
    any of them
}