rule TTP_XOR_QUAD_CurrentVersionRun_bcef {
  strings:
    $key_bcef = { ef 80 [2] cb 8e [2] e0 a2 [2] ce 80 [2] da 9b [2] d5 81 [2] cb 9c [2] c9 9d [2] d2 9b [2] ce 9c [2] d2 b3 }

  condition:
    any of them
}