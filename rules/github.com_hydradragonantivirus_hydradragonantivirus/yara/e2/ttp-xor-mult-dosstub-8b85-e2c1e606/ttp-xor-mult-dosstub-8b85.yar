rule TTP_XOR_MULT_DOSStub_8b85 {
  strings:
    $key_8b85 = { df ed [2] ab f5 [2] ec f7 [2] ab e6 [2] e5 ea [2] e9 e0 [2] fe eb [2] e5 a5 [2] d8 }

  condition:
    any of them
}