rule TTP_XOR_QUAD_CurrentVersionRun_10d5 {
  strings:
    $key_10d5 = { 43 ba [2] 67 b4 [2] 4c 98 [2] 62 ba [2] 76 a1 [2] 79 bb [2] 67 a6 [2] 65 a7 [2] 7e a1 [2] 62 a6 [2] 7e 89 }

  condition:
    any of them
}