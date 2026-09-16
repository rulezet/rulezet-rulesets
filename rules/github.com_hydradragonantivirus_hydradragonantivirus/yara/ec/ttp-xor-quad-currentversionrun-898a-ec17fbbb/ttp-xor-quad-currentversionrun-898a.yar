rule TTP_XOR_QUAD_CurrentVersionRun_898a {
  strings:
    $key_898a = { da e5 [2] fe eb [2] d5 c7 [2] fb e5 [2] ef fe [2] e0 e4 [2] fe f9 [2] fc f8 [2] e7 fe [2] fb f9 [2] e7 d6 }

  condition:
    any of them
}