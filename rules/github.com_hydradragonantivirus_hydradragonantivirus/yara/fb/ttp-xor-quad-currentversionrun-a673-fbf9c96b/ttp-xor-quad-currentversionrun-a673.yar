rule TTP_XOR_QUAD_CurrentVersionRun_a673 {
  strings:
    $key_a673 = { f5 1c [2] d1 12 [2] fa 3e [2] d4 1c [2] c0 07 [2] cf 1d [2] d1 00 [2] d3 01 [2] c8 07 [2] d4 00 [2] c8 2f }

  condition:
    any of them
}