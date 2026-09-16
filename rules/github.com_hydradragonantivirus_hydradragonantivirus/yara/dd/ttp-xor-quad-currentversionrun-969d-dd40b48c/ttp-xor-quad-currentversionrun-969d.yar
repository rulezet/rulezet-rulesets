rule TTP_XOR_QUAD_CurrentVersionRun_969d {
  strings:
    $key_969d = { c5 f2 [2] e1 fc [2] ca d0 [2] e4 f2 [2] f0 e9 [2] ff f3 [2] e1 ee [2] e3 ef [2] f8 e9 [2] e4 ee [2] f8 c1 }

  condition:
    any of them
}