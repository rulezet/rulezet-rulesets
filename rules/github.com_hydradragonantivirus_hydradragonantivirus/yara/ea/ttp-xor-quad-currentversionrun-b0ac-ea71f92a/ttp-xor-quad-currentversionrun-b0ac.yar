rule TTP_XOR_QUAD_CurrentVersionRun_b0ac {
  strings:
    $key_b0ac = { e3 c3 [2] c7 cd [2] ec e1 [2] c2 c3 [2] d6 d8 [2] d9 c2 [2] c7 df [2] c5 de [2] de d8 [2] c2 df [2] de f0 }

  condition:
    any of them
}