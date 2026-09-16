rule TTP_XOR_QUAD_CurrentVersionRun_fba6 {
  strings:
    $key_fba6 = { a8 c9 [2] 8c c7 [2] a7 eb [2] 89 c9 [2] 9d d2 [2] 92 c8 [2] 8c d5 [2] 8e d4 [2] 95 d2 [2] 89 d5 [2] 95 fa }

  condition:
    any of them
}