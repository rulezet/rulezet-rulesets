rule TTP_XOR_QUAD_CurrentVersionRun_b34e {
  strings:
    $key_b34e = { e0 21 [2] c4 2f [2] ef 03 [2] c1 21 [2] d5 3a [2] da 20 [2] c4 3d [2] c6 3c [2] dd 3a [2] c1 3d [2] dd 12 }

  condition:
    any of them
}