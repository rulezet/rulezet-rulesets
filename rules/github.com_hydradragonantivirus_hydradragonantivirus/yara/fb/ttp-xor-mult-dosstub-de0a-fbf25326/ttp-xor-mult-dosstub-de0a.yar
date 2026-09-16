rule TTP_XOR_MULT_DOSStub_de0a {
  strings:
    $key_de0a = { 8a 62 [2] fe 7a [2] b9 78 [2] fe 69 [2] b0 65 [2] bc 6f [2] ab 64 [2] b0 2a [2] 8d }

  condition:
    any of them
}