rule TTP_XOR_QUAD_CurrentVersionRun_89f4 {
  strings:
    $key_89f4 = { da 9b [2] fe 95 [2] d5 b9 [2] fb 9b [2] ef 80 [2] e0 9a [2] fe 87 [2] fc 86 [2] e7 80 [2] fb 87 [2] e7 a8 }

  condition:
    any of them
}