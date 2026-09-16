rule TTP_XOR_QUAD_CurrentVersionRun_89f5 {
  strings:
    $key_89f5 = { da 9a [2] fe 94 [2] d5 b8 [2] fb 9a [2] ef 81 [2] e0 9b [2] fe 86 [2] fc 87 [2] e7 81 [2] fb 86 [2] e7 a9 }

  condition:
    any of them
}