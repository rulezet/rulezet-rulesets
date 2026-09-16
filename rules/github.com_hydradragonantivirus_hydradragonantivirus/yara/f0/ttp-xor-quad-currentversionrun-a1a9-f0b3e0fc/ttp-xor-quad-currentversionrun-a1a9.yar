rule TTP_XOR_QUAD_CurrentVersionRun_a1a9 {
  strings:
    $key_a1a9 = { f2 c6 [2] d6 c8 [2] fd e4 [2] d3 c6 [2] c7 dd [2] c8 c7 [2] d6 da [2] d4 db [2] cf dd [2] d3 da [2] cf f5 }

  condition:
    any of them
}