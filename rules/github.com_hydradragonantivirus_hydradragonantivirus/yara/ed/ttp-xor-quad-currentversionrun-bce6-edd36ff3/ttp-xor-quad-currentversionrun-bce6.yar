rule TTP_XOR_QUAD_CurrentVersionRun_bce6 {
  strings:
    $key_bce6 = { ef 89 [2] cb 87 [2] e0 ab [2] ce 89 [2] da 92 [2] d5 88 [2] cb 95 [2] c9 94 [2] d2 92 [2] ce 95 [2] d2 ba }

  condition:
    any of them
}