rule TTP_XOR_QUAD_CurrentVersionRun_a6d5 {
  strings:
    $key_a6d5 = { f5 ba [2] d1 b4 [2] fa 98 [2] d4 ba [2] c0 a1 [2] cf bb [2] d1 a6 [2] d3 a7 [2] c8 a1 [2] d4 a6 [2] c8 89 }

  condition:
    any of them
}