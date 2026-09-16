rule TTP_XOR_QUAD_CurrentVersionRun_bc17 {
  strings:
    $key_bc17 = { ef 78 [2] cb 76 [2] e0 5a [2] ce 78 [2] da 63 [2] d5 79 [2] cb 64 [2] c9 65 [2] d2 63 [2] ce 64 [2] d2 4b }

  condition:
    any of them
}