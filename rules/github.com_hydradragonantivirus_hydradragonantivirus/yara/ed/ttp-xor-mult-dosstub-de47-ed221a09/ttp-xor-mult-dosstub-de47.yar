rule TTP_XOR_MULT_DOSStub_de47 {
  strings:
    $key_de47 = { 8a 2f [2] fe 37 [2] b9 35 [2] fe 24 [2] b0 28 [2] bc 22 [2] ab 29 [2] b0 67 [2] 8d }

  condition:
    any of them
}