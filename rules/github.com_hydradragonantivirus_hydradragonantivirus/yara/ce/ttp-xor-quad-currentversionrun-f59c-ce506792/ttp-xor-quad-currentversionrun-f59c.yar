rule TTP_XOR_QUAD_CurrentVersionRun_f59c {
  strings:
    $key_f59c = { a6 f3 [2] 82 fd [2] a9 d1 [2] 87 f3 [2] 93 e8 [2] 9c f2 [2] 82 ef [2] 80 ee [2] 9b e8 [2] 87 ef [2] 9b c0 }

  condition:
    any of them
}