rule TTP_XOR_QUAD_CurrentVersionRun_8909 {
  strings:
    $key_8909 = { da 66 [2] fe 68 [2] d5 44 [2] fb 66 [2] ef 7d [2] e0 67 [2] fe 7a [2] fc 7b [2] e7 7d [2] fb 7a [2] e7 55 }

  condition:
    any of them
}