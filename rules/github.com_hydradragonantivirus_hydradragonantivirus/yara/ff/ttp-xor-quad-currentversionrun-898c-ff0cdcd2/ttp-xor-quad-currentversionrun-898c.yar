rule TTP_XOR_QUAD_CurrentVersionRun_898c {
  strings:
    $key_898c = { da e3 [2] fe ed [2] d5 c1 [2] fb e3 [2] ef f8 [2] e0 e2 [2] fe ff [2] fc fe [2] e7 f8 [2] fb ff [2] e7 d0 }

  condition:
    any of them
}