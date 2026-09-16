rule TTP_XOR_MULT_DOSStub_de96 {
  strings:
    $key_de96 = { 8a fe [2] fe e6 [2] b9 e4 [2] fe f5 [2] b0 f9 [2] bc f3 [2] ab f8 [2] b0 b6 [2] 8d }

  condition:
    any of them
}