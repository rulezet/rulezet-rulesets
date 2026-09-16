rule TTP_XOR_QUAD_CurrentVersionRun_bc05 {
  strings:
    $key_bc05 = { ef 6a [2] cb 64 [2] e0 48 [2] ce 6a [2] da 71 [2] d5 6b [2] cb 76 [2] c9 77 [2] d2 71 [2] ce 76 [2] d2 59 }

  condition:
    any of them
}