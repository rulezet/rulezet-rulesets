rule TTP_XOR_QUAD_CurrentVersionRun_8958 {
  strings:
    $key_8958 = { da 37 [2] fe 39 [2] d5 15 [2] fb 37 [2] ef 2c [2] e0 36 [2] fe 2b [2] fc 2a [2] e7 2c [2] fb 2b [2] e7 04 }

  condition:
    any of them
}