rule TTP_XOR_MULT_DOSStub_de4a {
  strings:
    $key_de4a = { 8a 22 [2] fe 3a [2] b9 38 [2] fe 29 [2] b0 25 [2] bc 2f [2] ab 24 [2] b0 6a [2] 8d }

  condition:
    any of them
}