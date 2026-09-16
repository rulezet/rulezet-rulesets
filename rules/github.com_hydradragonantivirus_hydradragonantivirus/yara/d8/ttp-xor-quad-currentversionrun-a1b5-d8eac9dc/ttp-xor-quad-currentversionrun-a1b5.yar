rule TTP_XOR_QUAD_CurrentVersionRun_a1b5 {
  strings:
    $key_a1b5 = { f2 da [2] d6 d4 [2] fd f8 [2] d3 da [2] c7 c1 [2] c8 db [2] d6 c6 [2] d4 c7 [2] cf c1 [2] d3 c6 [2] cf e9 }

  condition:
    any of them
}