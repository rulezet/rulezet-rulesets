rule TTP_XOR_QUAD_CurrentVersionRun_bc5d {
  strings:
    $key_bc5d = { ef 32 [2] cb 3c [2] e0 10 [2] ce 32 [2] da 29 [2] d5 33 [2] cb 2e [2] c9 2f [2] d2 29 [2] ce 2e [2] d2 01 }

  condition:
    any of them
}