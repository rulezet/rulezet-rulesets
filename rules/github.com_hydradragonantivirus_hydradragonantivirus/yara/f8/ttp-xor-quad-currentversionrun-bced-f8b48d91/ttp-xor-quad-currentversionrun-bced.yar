rule TTP_XOR_QUAD_CurrentVersionRun_bced {
  strings:
    $key_bced = { ef 82 [2] cb 8c [2] e0 a0 [2] ce 82 [2] da 99 [2] d5 83 [2] cb 9e [2] c9 9f [2] d2 99 [2] ce 9e [2] d2 b1 }

  condition:
    any of them
}