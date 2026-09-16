rule TTP_XOR_QUAD_CurrentVersionRun_8978 {
  strings:
    $key_8978 = { da 17 [2] fe 19 [2] d5 35 [2] fb 17 [2] ef 0c [2] e0 16 [2] fe 0b [2] fc 0a [2] e7 0c [2] fb 0b [2] e7 24 }

  condition:
    any of them
}