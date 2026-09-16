rule TTP_XOR_QUAD_CurrentVersionRun_b773 {
  strings:
    $key_b773 = { e4 1c [2] c0 12 [2] eb 3e [2] c5 1c [2] d1 07 [2] de 1d [2] c0 00 [2] c2 01 [2] d9 07 [2] c5 00 [2] d9 2f }

  condition:
    any of them
}