rule TTP_XOR_QUAD_CurrentVersionRun_119c {
  strings:
    $key_119c = { 42 f3 [2] 66 fd [2] 4d d1 [2] 63 f3 [2] 77 e8 [2] 78 f2 [2] 66 ef [2] 64 ee [2] 7f e8 [2] 63 ef [2] 7f c0 }

  condition:
    any of them
}