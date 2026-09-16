rule TTP_XOR_QUAD_CurrentVersionRun_bc68 {
  strings:
    $key_bc68 = { ef 07 [2] cb 09 [2] e0 25 [2] ce 07 [2] da 1c [2] d5 06 [2] cb 1b [2] c9 1a [2] d2 1c [2] ce 1b [2] d2 34 }

  condition:
    any of them
}