rule TTP_XOR_QUAD_CurrentVersionRun_909d {
  strings:
    $key_909d = { c3 f2 [2] e7 fc [2] cc d0 [2] e2 f2 [2] f6 e9 [2] f9 f3 [2] e7 ee [2] e5 ef [2] fe e9 [2] e2 ee [2] fe c1 }

  condition:
    any of them
}