rule TTP_XOR_MULT_DOSStub_de42 {
  strings:
    $key_de42 = { 8a 2a [2] fe 32 [2] b9 30 [2] fe 21 [2] b0 2d [2] bc 27 [2] ab 2c [2] b0 62 [2] 8d }

  condition:
    any of them
}