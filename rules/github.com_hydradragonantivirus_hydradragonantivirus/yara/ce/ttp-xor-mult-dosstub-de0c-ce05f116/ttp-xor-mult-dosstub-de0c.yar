rule TTP_XOR_MULT_DOSStub_de0c {
  strings:
    $key_de0c = { 8a 64 [2] fe 7c [2] b9 7e [2] fe 6f [2] b0 63 [2] bc 69 [2] ab 62 [2] b0 2c [2] 8d }

  condition:
    any of them
}