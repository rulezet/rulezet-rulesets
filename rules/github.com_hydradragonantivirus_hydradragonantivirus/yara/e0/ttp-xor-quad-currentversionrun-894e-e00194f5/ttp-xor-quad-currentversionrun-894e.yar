rule TTP_XOR_QUAD_CurrentVersionRun_894e {
  strings:
    $key_894e = { da 21 [2] fe 2f [2] d5 03 [2] fb 21 [2] ef 3a [2] e0 20 [2] fe 3d [2] fc 3c [2] e7 3a [2] fb 3d [2] e7 12 }

  condition:
    any of them
}