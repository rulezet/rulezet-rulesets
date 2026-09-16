rule TTP_XOR_QUAD_CurrentVersionRun_bcfd {
  strings:
    $key_bcfd = { ef 92 [2] cb 9c [2] e0 b0 [2] ce 92 [2] da 89 [2] d5 93 [2] cb 8e [2] c9 8f [2] d2 89 [2] ce 8e [2] d2 a1 }

  condition:
    any of them
}