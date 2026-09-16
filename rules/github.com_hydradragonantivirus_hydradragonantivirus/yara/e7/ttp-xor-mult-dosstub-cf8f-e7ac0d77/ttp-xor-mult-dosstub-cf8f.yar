rule TTP_XOR_MULT_DOSStub_cf8f {
  strings:
    $key_cf8f = { 9b e7 [2] ef ff [2] a8 fd [2] ef ec [2] a1 e0 [2] ad ea [2] ba e1 [2] a1 af [2] 9c }

  condition:
    any of them
}