rule TTP_XOR_QUAD_CurrentVersionRun_bc70 {
  strings:
    $key_bc70 = { ef 1f [2] cb 11 [2] e0 3d [2] ce 1f [2] da 04 [2] d5 1e [2] cb 03 [2] c9 02 [2] d2 04 [2] ce 03 [2] d2 2c }

  condition:
    any of them
}