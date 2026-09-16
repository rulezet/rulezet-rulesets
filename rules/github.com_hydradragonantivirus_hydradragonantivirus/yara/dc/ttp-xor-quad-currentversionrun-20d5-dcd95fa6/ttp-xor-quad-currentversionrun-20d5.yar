rule TTP_XOR_QUAD_CurrentVersionRun_20d5 {
  strings:
    $key_20d5 = { 73 ba [2] 57 b4 [2] 7c 98 [2] 52 ba [2] 46 a1 [2] 49 bb [2] 57 a6 [2] 55 a7 [2] 4e a1 [2] 52 a6 [2] 4e 89 }

  condition:
    any of them
}