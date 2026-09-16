rule TTP_XOR_QUAD_CurrentVersionRun_bc3d {
  strings:
    $key_bc3d = { ef 52 [2] cb 5c [2] e0 70 [2] ce 52 [2] da 49 [2] d5 53 [2] cb 4e [2] c9 4f [2] d2 49 [2] ce 4e [2] d2 61 }

  condition:
    any of them
}