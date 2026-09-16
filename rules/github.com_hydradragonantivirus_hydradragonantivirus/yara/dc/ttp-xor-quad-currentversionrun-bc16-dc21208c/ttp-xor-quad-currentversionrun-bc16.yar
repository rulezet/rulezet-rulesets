rule TTP_XOR_QUAD_CurrentVersionRun_bc16 {
  strings:
    $key_bc16 = { ef 79 [2] cb 77 [2] e0 5b [2] ce 79 [2] da 62 [2] d5 78 [2] cb 65 [2] c9 64 [2] d2 62 [2] ce 65 [2] d2 4a }

  condition:
    any of them
}