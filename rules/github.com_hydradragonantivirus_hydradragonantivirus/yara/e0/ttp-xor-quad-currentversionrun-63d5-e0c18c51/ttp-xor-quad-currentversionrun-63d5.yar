rule TTP_XOR_QUAD_CurrentVersionRun_63d5 {
  strings:
    $key_63d5 = { 30 ba [2] 14 b4 [2] 3f 98 [2] 11 ba [2] 05 a1 [2] 0a bb [2] 14 a6 [2] 16 a7 [2] 0d a1 [2] 11 a6 [2] 0d 89 }

  condition:
    any of them
}