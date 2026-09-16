rule TTP_XOR_QUAD_CurrentVersionRun_a1b4 {
  strings:
    $key_a1b4 = { f2 db [2] d6 d5 [2] fd f9 [2] d3 db [2] c7 c0 [2] c8 da [2] d6 c7 [2] d4 c6 [2] cf c0 [2] d3 c7 [2] cf e8 }

  condition:
    any of them
}