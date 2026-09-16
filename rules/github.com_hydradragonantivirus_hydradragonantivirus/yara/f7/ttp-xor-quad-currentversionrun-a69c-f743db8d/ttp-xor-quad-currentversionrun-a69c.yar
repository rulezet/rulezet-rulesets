rule TTP_XOR_QUAD_CurrentVersionRun_a69c {
  strings:
    $key_a69c = { f5 f3 [2] d1 fd [2] fa d1 [2] d4 f3 [2] c0 e8 [2] cf f2 [2] d1 ef [2] d3 ee [2] c8 e8 [2] d4 ef [2] c8 c0 }

  condition:
    any of them
}