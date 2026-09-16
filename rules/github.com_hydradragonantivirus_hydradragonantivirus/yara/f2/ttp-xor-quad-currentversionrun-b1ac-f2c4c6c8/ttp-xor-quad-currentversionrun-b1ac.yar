rule TTP_XOR_QUAD_CurrentVersionRun_b1ac {
  strings:
    $key_b1ac = { e2 c3 [2] c6 cd [2] ed e1 [2] c3 c3 [2] d7 d8 [2] d8 c2 [2] c6 df [2] c4 de [2] df d8 [2] c3 df [2] df f0 }

  condition:
    any of them
}