rule TTP_XOR_QUAD_CurrentVersionRun_bc5a {
  strings:
    $key_bc5a = { ef 35 [2] cb 3b [2] e0 17 [2] ce 35 [2] da 2e [2] d5 34 [2] cb 29 [2] c9 28 [2] d2 2e [2] ce 29 [2] d2 06 }

  condition:
    any of them
}