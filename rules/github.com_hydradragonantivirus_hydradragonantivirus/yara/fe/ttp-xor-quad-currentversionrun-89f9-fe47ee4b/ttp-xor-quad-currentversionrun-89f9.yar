rule TTP_XOR_QUAD_CurrentVersionRun_89f9 {
  strings:
    $key_89f9 = { da 96 [2] fe 98 [2] d5 b4 [2] fb 96 [2] ef 8d [2] e0 97 [2] fe 8a [2] fc 8b [2] e7 8d [2] fb 8a [2] e7 a5 }

  condition:
    any of them
}