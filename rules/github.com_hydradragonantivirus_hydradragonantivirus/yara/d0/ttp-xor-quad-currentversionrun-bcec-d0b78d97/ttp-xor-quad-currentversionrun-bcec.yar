rule TTP_XOR_QUAD_CurrentVersionRun_bcec {
  strings:
    $key_bcec = { ef 83 [2] cb 8d [2] e0 a1 [2] ce 83 [2] da 98 [2] d5 82 [2] cb 9f [2] c9 9e [2] d2 98 [2] ce 9f [2] d2 b0 }

  condition:
    any of them
}