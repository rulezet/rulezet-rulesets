rule TTP_XOR_QUAD_CurrentVersionRun_f2a6 {
  strings:
    $key_f2a6 = { a1 c9 [2] 85 c7 [2] ae eb [2] 80 c9 [2] 94 d2 [2] 9b c8 [2] 85 d5 [2] 87 d4 [2] 9c d2 [2] 80 d5 [2] 9c fa }

  condition:
    any of them
}