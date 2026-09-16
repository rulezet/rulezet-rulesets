rule TTP_XOR_QUAD_CurrentVersionRun_56d4 {
  strings:
    $key_56d4 = { 05 bb [2] 21 b5 [2] 0a 99 [2] 24 bb [2] 30 a0 [2] 3f ba [2] 21 a7 [2] 23 a6 [2] 38 a0 [2] 24 a7 [2] 38 88 }

  condition:
    any of them
}