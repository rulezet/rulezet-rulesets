rule TTP_XOR_QUAD_CurrentVersionRun_fba8 {
  strings:
    $key_fba8 = { a8 c7 [2] 8c c9 [2] a7 e5 [2] 89 c7 [2] 9d dc [2] 92 c6 [2] 8c db [2] 8e da [2] 95 dc [2] 89 db [2] 95 f4 }

  condition:
    any of them
}