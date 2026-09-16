rule TTP_XOR_QUAD_CurrentVersionRun_f4c9 {
  strings:
    $key_f4c9 = { a7 a6 [2] 83 a8 [2] a8 84 [2] 86 a6 [2] 92 bd [2] 9d a7 [2] 83 ba [2] 81 bb [2] 9a bd [2] 86 ba [2] 9a 95 }

  condition:
    any of them
}