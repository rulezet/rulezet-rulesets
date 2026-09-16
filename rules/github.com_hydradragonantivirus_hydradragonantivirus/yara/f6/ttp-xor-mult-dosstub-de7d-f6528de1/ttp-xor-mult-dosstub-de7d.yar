rule TTP_XOR_MULT_DOSStub_de7d {
  strings:
    $key_de7d = { 8a 15 [2] fe 0d [2] b9 0f [2] fe 1e [2] b0 12 [2] bc 18 [2] ab 13 [2] b0 5d [2] 8d }

  condition:
    any of them
}