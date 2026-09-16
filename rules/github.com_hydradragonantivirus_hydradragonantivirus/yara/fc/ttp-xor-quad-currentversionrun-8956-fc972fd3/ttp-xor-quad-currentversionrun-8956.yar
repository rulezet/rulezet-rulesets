rule TTP_XOR_QUAD_CurrentVersionRun_8956 {
  strings:
    $key_8956 = { da 39 [2] fe 37 [2] d5 1b [2] fb 39 [2] ef 22 [2] e0 38 [2] fe 25 [2] fc 24 [2] e7 22 [2] fb 25 [2] e7 0a }

  condition:
    any of them
}