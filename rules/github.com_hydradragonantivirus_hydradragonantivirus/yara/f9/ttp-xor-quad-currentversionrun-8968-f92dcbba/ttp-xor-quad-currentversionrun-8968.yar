rule TTP_XOR_QUAD_CurrentVersionRun_8968 {
  strings:
    $key_8968 = { da 07 [2] fe 09 [2] d5 25 [2] fb 07 [2] ef 1c [2] e0 06 [2] fe 1b [2] fc 1a [2] e7 1c [2] fb 1b [2] e7 34 }

  condition:
    any of them
}