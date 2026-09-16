rule TTP_XOR_QUAD_CurrentVersionRun_e7d6 {
  strings:
    $key_e7d6 = { b4 b9 [2] 90 b7 [2] bb 9b [2] 95 b9 [2] 81 a2 [2] 8e b8 [2] 90 a5 [2] 92 a4 [2] 89 a2 [2] 95 a5 [2] 89 8a }

  condition:
    any of them
}