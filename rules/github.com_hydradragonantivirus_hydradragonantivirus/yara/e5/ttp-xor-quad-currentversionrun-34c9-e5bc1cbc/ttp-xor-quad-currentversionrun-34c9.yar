rule TTP_XOR_QUAD_CurrentVersionRun_34c9 {
  strings:
    $key_34c9 = { 67 a6 [2] 43 a8 [2] 68 84 [2] 46 a6 [2] 52 bd [2] 5d a7 [2] 43 ba [2] 41 bb [2] 5a bd [2] 46 ba [2] 5a 95 }

  condition:
    any of them
}