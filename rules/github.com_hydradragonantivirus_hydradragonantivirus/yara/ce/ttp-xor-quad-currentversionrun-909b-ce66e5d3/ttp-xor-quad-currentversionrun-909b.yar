rule TTP_XOR_QUAD_CurrentVersionRun_909b {
  strings:
    $key_909b = { c3 f4 [2] e7 fa [2] cc d6 [2] e2 f4 [2] f6 ef [2] f9 f5 [2] e7 e8 [2] e5 e9 [2] fe ef [2] e2 e8 [2] fe c7 }

  condition:
    any of them
}