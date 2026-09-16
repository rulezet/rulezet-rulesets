rule TTP_XOR_MULT_DOSStub_de49 {
  strings:
    $key_de49 = { 8a 21 [2] fe 39 [2] b9 3b [2] fe 2a [2] b0 26 [2] bc 2c [2] ab 27 [2] b0 69 [2] 8d }

  condition:
    any of them
}