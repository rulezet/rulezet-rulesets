rule TTP_XOR_QUAD_CurrentVersionRun_bc53 {
  strings:
    $key_bc53 = { ef 3c [2] cb 32 [2] e0 1e [2] ce 3c [2] da 27 [2] d5 3d [2] cb 20 [2] c9 21 [2] d2 27 [2] ce 20 [2] d2 0f }

  condition:
    any of them
}