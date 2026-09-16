rule TTP_XOR_QUAD_CurrentVersionRun_719c {
  strings:
    $key_719c = { 22 f3 [2] 06 fd [2] 2d d1 [2] 03 f3 [2] 17 e8 [2] 18 f2 [2] 06 ef [2] 04 ee [2] 1f e8 [2] 03 ef [2] 1f c0 }

  condition:
    any of them
}