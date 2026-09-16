rule TTP_XOR_QUAD_CurrentVersionRun_00d5 {
  strings:
    $key_00d5 = { 53 ba [2] 77 b4 [2] 5c 98 [2] 72 ba [2] 66 a1 [2] 69 bb [2] 77 a6 [2] 75 a7 [2] 6e a1 [2] 72 a6 [2] 6e 89 }

  condition:
    any of them
}