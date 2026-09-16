rule TTP_XOR_QUAD_CurrentVersionRun_63c9 {
  strings:
    $key_63c9 = { 30 a6 [2] 14 a8 [2] 3f 84 [2] 11 a6 [2] 05 bd [2] 0a a7 [2] 14 ba [2] 16 bb [2] 0d bd [2] 11 ba [2] 0d 95 }

  condition:
    any of them
}