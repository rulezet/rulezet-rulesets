rule TTP_XOR_MULT_DOSStub_de15 {
  strings:
    $key_de15 = { 8a 7d [2] fe 65 [2] b9 67 [2] fe 76 [2] b0 7a [2] bc 70 [2] ab 7b [2] b0 35 [2] 8d }

  condition:
    any of them
}