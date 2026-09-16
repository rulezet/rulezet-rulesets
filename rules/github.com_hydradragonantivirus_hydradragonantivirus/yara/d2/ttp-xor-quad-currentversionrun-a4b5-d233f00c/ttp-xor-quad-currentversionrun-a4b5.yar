rule TTP_XOR_QUAD_CurrentVersionRun_a4b5 {
  strings:
    $key_a4b5 = { f7 da [2] d3 d4 [2] f8 f8 [2] d6 da [2] c2 c1 [2] cd db [2] d3 c6 [2] d1 c7 [2] ca c1 [2] d6 c6 [2] ca e9 }

  condition:
    any of them
}