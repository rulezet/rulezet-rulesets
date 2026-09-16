rule TTP_XOR_QUAD_CurrentVersionRun_bc6b {
  strings:
    $key_bc6b = { ef 04 [2] cb 0a [2] e0 26 [2] ce 04 [2] da 1f [2] d5 05 [2] cb 18 [2] c9 19 [2] d2 1f [2] ce 18 [2] d2 37 }

  condition:
    any of them
}