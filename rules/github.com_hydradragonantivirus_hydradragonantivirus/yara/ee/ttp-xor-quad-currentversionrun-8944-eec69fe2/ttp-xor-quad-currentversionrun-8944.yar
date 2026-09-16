rule TTP_XOR_QUAD_CurrentVersionRun_8944 {
  strings:
    $key_8944 = { da 2b [2] fe 25 [2] d5 09 [2] fb 2b [2] ef 30 [2] e0 2a [2] fe 37 [2] fc 36 [2] e7 30 [2] fb 37 [2] e7 18 }

  condition:
    any of them
}