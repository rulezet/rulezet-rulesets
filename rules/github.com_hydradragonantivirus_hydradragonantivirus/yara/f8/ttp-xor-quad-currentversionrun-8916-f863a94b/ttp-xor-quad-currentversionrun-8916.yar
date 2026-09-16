rule TTP_XOR_QUAD_CurrentVersionRun_8916 {
  strings:
    $key_8916 = { da 79 [2] fe 77 [2] d5 5b [2] fb 79 [2] ef 62 [2] e0 78 [2] fe 65 [2] fc 64 [2] e7 62 [2] fb 65 [2] e7 4a }

  condition:
    any of them
}