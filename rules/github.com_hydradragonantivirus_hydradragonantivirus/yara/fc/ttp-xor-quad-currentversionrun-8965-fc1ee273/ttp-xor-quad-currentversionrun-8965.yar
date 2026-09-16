rule TTP_XOR_QUAD_CurrentVersionRun_8965 {
  strings:
    $key_8965 = { da 0a [2] fe 04 [2] d5 28 [2] fb 0a [2] ef 11 [2] e0 0b [2] fe 16 [2] fc 17 [2] e7 11 [2] fb 16 [2] e7 39 }

  condition:
    any of them
}