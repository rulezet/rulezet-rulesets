rule TTP_XOR_QUAD_CurrentVersionRun_8947 {
  strings:
    $key_8947 = { da 28 [2] fe 26 [2] d5 0a [2] fb 28 [2] ef 33 [2] e0 29 [2] fe 34 [2] fc 35 [2] e7 33 [2] fb 34 [2] e7 1b }

  condition:
    any of them
}