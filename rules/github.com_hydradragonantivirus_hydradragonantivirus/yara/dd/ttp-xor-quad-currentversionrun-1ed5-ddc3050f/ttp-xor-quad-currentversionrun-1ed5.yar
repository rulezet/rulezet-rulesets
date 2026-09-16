rule TTP_XOR_QUAD_CurrentVersionRun_1ed5 {
  strings:
    $key_1ed5 = { 4d ba [2] 69 b4 [2] 42 98 [2] 6c ba [2] 78 a1 [2] 77 bb [2] 69 a6 [2] 6b a7 [2] 70 a1 [2] 6c a6 [2] 70 89 }

  condition:
    any of them
}