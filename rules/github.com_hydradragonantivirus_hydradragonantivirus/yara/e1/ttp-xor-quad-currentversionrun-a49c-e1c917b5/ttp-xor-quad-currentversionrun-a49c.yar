rule TTP_XOR_QUAD_CurrentVersionRun_a49c {
  strings:
    $key_a49c = { f7 f3 [2] d3 fd [2] f8 d1 [2] d6 f3 [2] c2 e8 [2] cd f2 [2] d3 ef [2] d1 ee [2] ca e8 [2] d6 ef [2] ca c0 }

  condition:
    any of them
}