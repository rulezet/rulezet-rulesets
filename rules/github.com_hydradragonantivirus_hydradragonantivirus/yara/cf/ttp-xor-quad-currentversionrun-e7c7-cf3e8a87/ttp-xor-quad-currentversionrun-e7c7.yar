rule TTP_XOR_QUAD_CurrentVersionRun_e7c7 {
  strings:
    $key_e7c7 = { b4 a8 [2] 90 a6 [2] bb 8a [2] 95 a8 [2] 81 b3 [2] 8e a9 [2] 90 b4 [2] 92 b5 [2] 89 b3 [2] 95 b4 [2] 89 9b }

  condition:
    any of them
}