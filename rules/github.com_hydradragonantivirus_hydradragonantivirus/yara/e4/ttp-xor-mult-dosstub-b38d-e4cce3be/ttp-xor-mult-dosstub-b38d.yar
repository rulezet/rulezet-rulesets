rule TTP_XOR_MULT_DOSStub_b38d {
  strings:
    $key_b38d = { e7 e5 [2] 93 fd [2] d4 ff [2] 93 ee [2] dd e2 [2] d1 e8 [2] c6 e3 [2] dd ad [2] e0 }

  condition:
    any of them
}