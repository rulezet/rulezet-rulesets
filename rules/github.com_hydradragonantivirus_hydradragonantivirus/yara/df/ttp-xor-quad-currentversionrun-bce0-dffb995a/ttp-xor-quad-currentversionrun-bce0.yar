rule TTP_XOR_QUAD_CurrentVersionRun_bce0 {
  strings:
    $key_bce0 = { ef 8f [2] cb 81 [2] e0 ad [2] ce 8f [2] da 94 [2] d5 8e [2] cb 93 [2] c9 92 [2] d2 94 [2] ce 93 [2] d2 bc }

  condition:
    any of them
}