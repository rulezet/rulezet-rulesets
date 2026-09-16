rule TTP_XOR_QUAD_CurrentVersionRun_0ed5 {
  strings:
    $key_0ed5 = { 5d ba [2] 79 b4 [2] 52 98 [2] 7c ba [2] 68 a1 [2] 67 bb [2] 79 a6 [2] 7b a7 [2] 60 a1 [2] 7c a6 [2] 60 89 }

  condition:
    any of them
}