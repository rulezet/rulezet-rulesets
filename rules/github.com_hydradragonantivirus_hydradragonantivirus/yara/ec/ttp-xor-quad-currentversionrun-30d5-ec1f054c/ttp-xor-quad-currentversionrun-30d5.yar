rule TTP_XOR_QUAD_CurrentVersionRun_30d5 {
  strings:
    $key_30d5 = { 63 ba [2] 47 b4 [2] 6c 98 [2] 42 ba [2] 56 a1 [2] 59 bb [2] 47 a6 [2] 45 a7 [2] 5e a1 [2] 42 a6 [2] 5e 89 }

  condition:
    any of them
}