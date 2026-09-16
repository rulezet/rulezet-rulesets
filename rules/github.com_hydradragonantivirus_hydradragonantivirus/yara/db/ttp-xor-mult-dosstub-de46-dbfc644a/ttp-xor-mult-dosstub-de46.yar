rule TTP_XOR_MULT_DOSStub_de46 {
  strings:
    $key_de46 = { 8a 2e [2] fe 36 [2] b9 34 [2] fe 25 [2] b0 29 [2] bc 23 [2] ab 28 [2] b0 66 [2] 8d }

  condition:
    any of them
}