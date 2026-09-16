rule TTP_XOR_QUAD_CurrentVersionRun_a1a8 {
  strings:
    $key_a1a8 = { f2 c7 [2] d6 c9 [2] fd e5 [2] d3 c7 [2] c7 dc [2] c8 c6 [2] d6 db [2] d4 da [2] cf dc [2] d3 db [2] cf f4 }

  condition:
    any of them
}