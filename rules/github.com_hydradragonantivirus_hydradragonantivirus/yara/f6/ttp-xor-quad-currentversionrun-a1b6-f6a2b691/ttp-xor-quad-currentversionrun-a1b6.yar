rule TTP_XOR_QUAD_CurrentVersionRun_a1b6 {
  strings:
    $key_a1b6 = { f2 d9 [2] d6 d7 [2] fd fb [2] d3 d9 [2] c7 c2 [2] c8 d8 [2] d6 c5 [2] d4 c4 [2] cf c2 [2] d3 c5 [2] cf ea }

  condition:
    any of them
}