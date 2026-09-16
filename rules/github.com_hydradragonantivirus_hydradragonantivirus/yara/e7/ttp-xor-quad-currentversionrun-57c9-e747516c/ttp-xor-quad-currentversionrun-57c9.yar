rule TTP_XOR_QUAD_CurrentVersionRun_57c9 {
  strings:
    $key_57c9 = { 04 a6 [2] 20 a8 [2] 0b 84 [2] 25 a6 [2] 31 bd [2] 3e a7 [2] 20 ba [2] 22 bb [2] 39 bd [2] 25 ba [2] 39 95 }

  condition:
    any of them
}