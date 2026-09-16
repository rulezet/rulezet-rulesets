rule TTP_XOR_QUAD_CurrentVersionRun_01c9 {
  strings:
    $key_01c9 = { 52 a6 [2] 76 a8 [2] 5d 84 [2] 73 a6 [2] 67 bd [2] 68 a7 [2] 76 ba [2] 74 bb [2] 6f bd [2] 73 ba [2] 6f 95 }

  condition:
    any of them
}