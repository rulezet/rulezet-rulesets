rule TTP_XOR_QUAD_CurrentVersionRun_bc75 {
  strings:
    $key_bc75 = { ef 1a [2] cb 14 [2] e0 38 [2] ce 1a [2] da 01 [2] d5 1b [2] cb 06 [2] c9 07 [2] d2 01 [2] ce 06 [2] d2 29 }

  condition:
    any of them
}