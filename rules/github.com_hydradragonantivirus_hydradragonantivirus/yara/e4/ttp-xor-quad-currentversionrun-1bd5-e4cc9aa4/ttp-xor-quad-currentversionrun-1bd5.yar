rule TTP_XOR_QUAD_CurrentVersionRun_1bd5 {
  strings:
    $key_1bd5 = { 48 ba [2] 6c b4 [2] 47 98 [2] 69 ba [2] 7d a1 [2] 72 bb [2] 6c a6 [2] 6e a7 [2] 75 a1 [2] 69 a6 [2] 75 89 }

  condition:
    any of them
}