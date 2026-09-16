rule TTP_XOR_QUAD_CurrentVersionRun_b0b5 {
  strings:
    $key_b0b5 = { e3 da [2] c7 d4 [2] ec f8 [2] c2 da [2] d6 c1 [2] d9 db [2] c7 c6 [2] c5 c7 [2] de c1 [2] c2 c6 [2] de e9 }

  condition:
    any of them
}