rule TTP_XOR_QUAD_CurrentVersionRun_a676 {
  strings:
    $key_a676 = { f5 19 [2] d1 17 [2] fa 3b [2] d4 19 [2] c0 02 [2] cf 18 [2] d1 05 [2] d3 04 [2] c8 02 [2] d4 05 [2] c8 2a }

  condition:
    any of them
}