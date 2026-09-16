rule TTP_XOR_QUAD_CurrentVersionRun_f39c {
  strings:
    $key_f39c = { a0 f3 [2] 84 fd [2] af d1 [2] 81 f3 [2] 95 e8 [2] 9a f2 [2] 84 ef [2] 86 ee [2] 9d e8 [2] 81 ef [2] 9d c0 }

  condition:
    any of them
}