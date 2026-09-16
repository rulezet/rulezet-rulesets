rule TTP_XOR_QUAD_CurrentVersionRun_a496 {
  strings:
    $key_a496 = { f7 f9 [2] d3 f7 [2] f8 db [2] d6 f9 [2] c2 e2 [2] cd f8 [2] d3 e5 [2] d1 e4 [2] ca e2 [2] d6 e5 [2] ca ca }

  condition:
    any of them
}