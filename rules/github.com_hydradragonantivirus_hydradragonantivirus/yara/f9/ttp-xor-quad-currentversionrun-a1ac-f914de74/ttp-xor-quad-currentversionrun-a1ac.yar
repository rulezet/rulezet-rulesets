rule TTP_XOR_QUAD_CurrentVersionRun_a1ac {
  strings:
    $key_a1ac = { f2 c3 [2] d6 cd [2] fd e1 [2] d3 c3 [2] c7 d8 [2] c8 c2 [2] d6 df [2] d4 de [2] cf d8 [2] d3 df [2] cf f0 }

  condition:
    any of them
}