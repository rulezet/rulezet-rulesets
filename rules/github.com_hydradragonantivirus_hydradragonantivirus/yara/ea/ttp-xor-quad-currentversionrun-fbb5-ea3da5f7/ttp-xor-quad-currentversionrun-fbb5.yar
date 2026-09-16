rule TTP_XOR_QUAD_CurrentVersionRun_fbb5 {
  strings:
    $key_fbb5 = { a8 da [2] 8c d4 [2] a7 f8 [2] 89 da [2] 9d c1 [2] 92 db [2] 8c c6 [2] 8e c7 [2] 95 c1 [2] 89 c6 [2] 95 e9 }

  condition:
    any of them
}