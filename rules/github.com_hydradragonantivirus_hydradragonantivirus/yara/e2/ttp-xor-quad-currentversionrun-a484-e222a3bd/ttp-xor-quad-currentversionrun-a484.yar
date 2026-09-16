rule TTP_XOR_QUAD_CurrentVersionRun_a484 {
  strings:
    $key_a484 = { f7 eb [2] d3 e5 [2] f8 c9 [2] d6 eb [2] c2 f0 [2] cd ea [2] d3 f7 [2] d1 f6 [2] ca f0 [2] d6 f7 [2] ca d8 }

  condition:
    any of them
}