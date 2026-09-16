rule TTP_XOR_QUAD_CurrentVersionRun_f596 {
  strings:
    $key_f596 = { a6 f9 [2] 82 f7 [2] a9 db [2] 87 f9 [2] 93 e2 [2] 9c f8 [2] 82 e5 [2] 80 e4 [2] 9b e2 [2] 87 e5 [2] 9b ca }

  condition:
    any of them
}