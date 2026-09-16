rule TTP_XOR_QUAD_CurrentVersionRun_bc4b {
  strings:
    $key_bc4b = { ef 24 [2] cb 2a [2] e0 06 [2] ce 24 [2] da 3f [2] d5 25 [2] cb 38 [2] c9 39 [2] d2 3f [2] ce 38 [2] d2 17 }

  condition:
    any of them
}