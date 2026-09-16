rule TTP_XOR_QUAD_CurrentVersionRun_f59d {
  strings:
    $key_f59d = { a6 f2 [2] 82 fc [2] a9 d0 [2] 87 f2 [2] 93 e9 [2] 9c f3 [2] 82 ee [2] 80 ef [2] 9b e9 [2] 87 ee [2] 9b c1 }

  condition:
    any of them
}