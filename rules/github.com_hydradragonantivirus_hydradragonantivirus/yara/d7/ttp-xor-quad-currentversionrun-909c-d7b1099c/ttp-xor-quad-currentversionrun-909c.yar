rule TTP_XOR_QUAD_CurrentVersionRun_909c {
  strings:
    $key_909c = { c3 f3 [2] e7 fd [2] cc d1 [2] e2 f3 [2] f6 e8 [2] f9 f2 [2] e7 ef [2] e5 ee [2] fe e8 [2] e2 ef [2] fe c0 }

  condition:
    any of them
}