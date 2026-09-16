rule TTP_XOR_QUAD_CurrentVersionRun_8903 {
  strings:
    $key_8903 = { da 6c [2] fe 62 [2] d5 4e [2] fb 6c [2] ef 77 [2] e0 6d [2] fe 70 [2] fc 71 [2] e7 77 [2] fb 70 [2] e7 5f }

  condition:
    any of them
}