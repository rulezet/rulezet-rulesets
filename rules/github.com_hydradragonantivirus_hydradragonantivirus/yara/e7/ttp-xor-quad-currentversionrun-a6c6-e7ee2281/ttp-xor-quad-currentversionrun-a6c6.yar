rule TTP_XOR_QUAD_CurrentVersionRun_a6c6 {
  strings:
    $key_a6c6 = { f5 a9 [2] d1 a7 [2] fa 8b [2] d4 a9 [2] c0 b2 [2] cf a8 [2] d1 b5 [2] d3 b4 [2] c8 b2 [2] d4 b5 [2] c8 9a }

  condition:
    any of them
}