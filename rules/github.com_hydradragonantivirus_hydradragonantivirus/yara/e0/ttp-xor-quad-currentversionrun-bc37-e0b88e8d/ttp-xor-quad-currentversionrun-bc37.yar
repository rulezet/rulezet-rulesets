rule TTP_XOR_QUAD_CurrentVersionRun_bc37 {
  strings:
    $key_bc37 = { ef 58 [2] cb 56 [2] e0 7a [2] ce 58 [2] da 43 [2] d5 59 [2] cb 44 [2] c9 45 [2] d2 43 [2] ce 44 [2] d2 6b }

  condition:
    any of them
}