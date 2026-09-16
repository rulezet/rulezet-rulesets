rule TTP_XOR_MULT_DOSStub_de89 {
  strings:
    $key_de89 = { 8a e1 [2] fe f9 [2] b9 fb [2] fe ea [2] b0 e6 [2] bc ec [2] ab e7 [2] b0 a9 [2] 8d }

  condition:
    any of them
}