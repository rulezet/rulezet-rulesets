rule TTP_XOR_QUAD_CurrentVersionRun_bc20 {
  strings:
    $key_bc20 = { ef 4f [2] cb 41 [2] e0 6d [2] ce 4f [2] da 54 [2] d5 4e [2] cb 53 [2] c9 52 [2] d2 54 [2] ce 53 [2] d2 7c }

  condition:
    any of them
}