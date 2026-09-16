rule TTP_XOR_QUAD_CurrentVersionRun_b75c {
  strings:
    $key_b75c = { e4 33 [2] c0 3d [2] eb 11 [2] c5 33 [2] d1 28 [2] de 32 [2] c0 2f [2] c2 2e [2] d9 28 [2] c5 2f [2] d9 00 }

  condition:
    any of them
}