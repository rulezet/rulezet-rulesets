rule TTP_XOR_QUAD_CurrentVersionRun_bc41 {
  strings:
    $key_bc41 = { ef 2e [2] cb 20 [2] e0 0c [2] ce 2e [2] da 35 [2] d5 2f [2] cb 32 [2] c9 33 [2] d2 35 [2] ce 32 [2] d2 1d }

  condition:
    any of them
}