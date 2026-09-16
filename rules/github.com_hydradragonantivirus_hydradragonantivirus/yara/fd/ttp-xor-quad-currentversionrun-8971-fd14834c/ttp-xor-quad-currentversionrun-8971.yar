rule TTP_XOR_QUAD_CurrentVersionRun_8971 {
  strings:
    $key_8971 = { da 1e [2] fe 10 [2] d5 3c [2] fb 1e [2] ef 05 [2] e0 1f [2] fe 02 [2] fc 03 [2] e7 05 [2] fb 02 [2] e7 2d }

  condition:
    any of them
}