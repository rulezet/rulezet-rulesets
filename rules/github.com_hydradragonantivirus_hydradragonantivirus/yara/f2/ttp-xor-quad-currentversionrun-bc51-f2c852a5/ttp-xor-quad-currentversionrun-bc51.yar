rule TTP_XOR_QUAD_CurrentVersionRun_bc51 {
  strings:
    $key_bc51 = { ef 3e [2] cb 30 [2] e0 1c [2] ce 3e [2] da 25 [2] d5 3f [2] cb 22 [2] c9 23 [2] d2 25 [2] ce 22 [2] d2 0d }

  condition:
    any of them
}