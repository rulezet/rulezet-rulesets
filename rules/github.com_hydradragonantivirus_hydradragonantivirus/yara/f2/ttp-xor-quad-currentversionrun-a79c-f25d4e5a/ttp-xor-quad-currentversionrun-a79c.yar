rule TTP_XOR_QUAD_CurrentVersionRun_a79c {
  strings:
    $key_a79c = { f4 f3 [2] d0 fd [2] fb d1 [2] d5 f3 [2] c1 e8 [2] ce f2 [2] d0 ef [2] d2 ee [2] c9 e8 [2] d5 ef [2] c9 c0 }

  condition:
    any of them
}