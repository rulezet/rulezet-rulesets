rule TTP_XOR_QUAD_CurrentVersionRun_b0b4 {
  strings:
    $key_b0b4 = { e3 db [2] c7 d5 [2] ec f9 [2] c2 db [2] d6 c0 [2] d9 da [2] c7 c7 [2] c5 c6 [2] de c0 [2] c2 c7 [2] de e8 }

  condition:
    any of them
}