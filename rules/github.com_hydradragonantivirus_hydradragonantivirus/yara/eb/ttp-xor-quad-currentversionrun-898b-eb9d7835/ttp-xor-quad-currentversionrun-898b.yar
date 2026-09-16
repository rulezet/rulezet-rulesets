rule TTP_XOR_QUAD_CurrentVersionRun_898b {
  strings:
    $key_898b = { da e4 [2] fe ea [2] d5 c6 [2] fb e4 [2] ef ff [2] e0 e5 [2] fe f8 [2] fc f9 [2] e7 ff [2] fb f8 [2] e7 d7 }

  condition:
    any of them
}