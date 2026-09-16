rule TTP_XOR_QUAD_CurrentVersionRun_bc60 {
  strings:
    $key_bc60 = { ef 0f [2] cb 01 [2] e0 2d [2] ce 0f [2] da 14 [2] d5 0e [2] cb 13 [2] c9 12 [2] d2 14 [2] ce 13 [2] d2 3c }

  condition:
    any of them
}