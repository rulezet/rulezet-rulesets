rule TTP_XOR_QUAD_CurrentVersionRun_bc63 {
  strings:
    $key_bc63 = { ef 0c [2] cb 02 [2] e0 2e [2] ce 0c [2] da 17 [2] d5 0d [2] cb 10 [2] c9 11 [2] d2 17 [2] ce 10 [2] d2 3f }

  condition:
    any of them
}