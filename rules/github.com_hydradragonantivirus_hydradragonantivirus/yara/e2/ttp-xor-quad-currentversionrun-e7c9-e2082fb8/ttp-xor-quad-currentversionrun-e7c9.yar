rule TTP_XOR_QUAD_CurrentVersionRun_e7c9 {
  strings:
    $key_e7c9 = { b4 a6 [2] 90 a8 [2] bb 84 [2] 95 a6 [2] 81 bd [2] 8e a7 [2] 90 ba [2] 92 bb [2] 89 bd [2] 95 ba [2] 89 95 }

  condition:
    any of them
}