rule TTP_XOR_MULT_DOSStub_ae8f {
  strings:
    $key_ae8f = { fa e7 [2] 8e ff [2] c9 fd [2] 8e ec [2] c0 e0 [2] cc ea [2] db e1 [2] c0 af [2] fd }

  condition:
    any of them
}