rule TTP_XOR_QUAD_CurrentVersionRun_a7ac {
  strings:
    $key_a7ac = { f4 c3 [2] d0 cd [2] fb e1 [2] d5 c3 [2] c1 d8 [2] ce c2 [2] d0 df [2] d2 de [2] c9 d8 [2] d5 df [2] c9 f0 }

  condition:
    any of them
}