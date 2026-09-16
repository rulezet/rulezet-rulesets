rule TTP_XOR_QUAD_CurrentVersionRun_89e5 {
  strings:
    $key_89e5 = { da 8a [2] fe 84 [2] d5 a8 [2] fb 8a [2] ef 91 [2] e0 8b [2] fe 96 [2] fc 97 [2] e7 91 [2] fb 96 [2] e7 b9 }

  condition:
    any of them
}