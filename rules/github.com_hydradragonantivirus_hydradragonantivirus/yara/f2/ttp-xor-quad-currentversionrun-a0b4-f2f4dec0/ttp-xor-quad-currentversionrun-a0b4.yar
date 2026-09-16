rule TTP_XOR_QUAD_CurrentVersionRun_a0b4 {
  strings:
    $key_a0b4 = { f3 db [2] d7 d5 [2] fc f9 [2] d2 db [2] c6 c0 [2] c9 da [2] d7 c7 [2] d5 c6 [2] ce c0 [2] d2 c7 [2] ce e8 }

  condition:
    any of them
}