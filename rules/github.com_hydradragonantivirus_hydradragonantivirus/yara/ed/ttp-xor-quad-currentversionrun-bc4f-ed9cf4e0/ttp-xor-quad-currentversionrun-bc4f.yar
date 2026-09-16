rule TTP_XOR_QUAD_CurrentVersionRun_bc4f {
  strings:
    $key_bc4f = { ef 20 [2] cb 2e [2] e0 02 [2] ce 20 [2] da 3b [2] d5 21 [2] cb 3c [2] c9 3d [2] d2 3b [2] ce 3c [2] d2 13 }

  condition:
    any of them
}