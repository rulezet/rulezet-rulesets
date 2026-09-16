rule TTP_XOR_QUAD_CurrentVersionRun_d19c {
  strings:
    $key_d19c = { 82 f3 [2] a6 fd [2] 8d d1 [2] a3 f3 [2] b7 e8 [2] b8 f2 [2] a6 ef [2] a4 ee [2] bf e8 [2] a3 ef [2] bf c0 }

  condition:
    any of them
}