rule TTP_XOR_QUAD_CurrentVersionRun_a646 {
  strings:
    $key_a646 = { f5 29 [2] d1 27 [2] fa 0b [2] d4 29 [2] c0 32 [2] cf 28 [2] d1 35 [2] d3 34 [2] c8 32 [2] d4 35 [2] c8 1a }

  condition:
    any of them
}