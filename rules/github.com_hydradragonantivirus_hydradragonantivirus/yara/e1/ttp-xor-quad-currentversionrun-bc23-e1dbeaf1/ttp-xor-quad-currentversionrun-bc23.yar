rule TTP_XOR_QUAD_CurrentVersionRun_bc23 {
  strings:
    $key_bc23 = { ef 4c [2] cb 42 [2] e0 6e [2] ce 4c [2] da 57 [2] d5 4d [2] cb 50 [2] c9 51 [2] d2 57 [2] ce 50 [2] d2 7f }

  condition:
    any of them
}