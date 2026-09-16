rule TTP_XOR_MULT_DOSStub_de3a {
  strings:
    $key_de3a = { 8a 52 [2] fe 4a [2] b9 48 [2] fe 59 [2] b0 55 [2] bc 5f [2] ab 54 [2] b0 1a [2] 8d }

  condition:
    any of them
}