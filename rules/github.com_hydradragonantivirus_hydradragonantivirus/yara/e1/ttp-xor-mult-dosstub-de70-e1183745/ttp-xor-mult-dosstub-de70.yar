rule TTP_XOR_MULT_DOSStub_de70 {
  strings:
    $key_de70 = { 8a 18 [2] fe 00 [2] b9 02 [2] fe 13 [2] b0 1f [2] bc 15 [2] ab 1e [2] b0 50 [2] 8d }

  condition:
    any of them
}