rule TTP_XOR_QUAD_CurrentVersionRun_8954 {
  strings:
    $key_8954 = { da 3b [2] fe 35 [2] d5 19 [2] fb 3b [2] ef 20 [2] e0 3a [2] fe 27 [2] fc 26 [2] e7 20 [2] fb 27 [2] e7 08 }

  condition:
    any of them
}