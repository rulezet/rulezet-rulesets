rule TTP_XOR_QUAD_CurrentVersionRun_019c {
  strings:
    $key_019c = { 52 f3 [2] 76 fd [2] 5d d1 [2] 73 f3 [2] 67 e8 [2] 68 f2 [2] 76 ef [2] 74 ee [2] 6f e8 [2] 73 ef [2] 6f c0 }

  condition:
    any of them
}