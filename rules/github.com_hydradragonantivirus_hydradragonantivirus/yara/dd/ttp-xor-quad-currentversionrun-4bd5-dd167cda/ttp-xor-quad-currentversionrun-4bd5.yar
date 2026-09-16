rule TTP_XOR_QUAD_CurrentVersionRun_4bd5 {
  strings:
    $key_4bd5 = { 18 ba [2] 3c b4 [2] 17 98 [2] 39 ba [2] 2d a1 [2] 22 bb [2] 3c a6 [2] 3e a7 [2] 25 a1 [2] 39 a6 [2] 25 89 }

  condition:
    any of them
}