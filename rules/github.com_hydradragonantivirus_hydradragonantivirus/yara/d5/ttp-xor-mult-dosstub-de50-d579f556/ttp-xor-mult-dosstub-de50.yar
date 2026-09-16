rule TTP_XOR_MULT_DOSStub_de50 {
  strings:
    $key_de50 = { 8a 38 [2] fe 20 [2] b9 22 [2] fe 33 [2] b0 3f [2] bc 35 [2] ab 3e [2] b0 70 [2] 8d }

  condition:
    any of them
}