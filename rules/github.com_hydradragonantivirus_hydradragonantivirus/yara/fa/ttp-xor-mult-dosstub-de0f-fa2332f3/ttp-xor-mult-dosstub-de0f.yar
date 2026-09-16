rule TTP_XOR_MULT_DOSStub_de0f {
  strings:
    $key_de0f = { 8a 67 [2] fe 7f [2] b9 7d [2] fe 6c [2] b0 60 [2] bc 6a [2] ab 61 [2] b0 2f [2] 8d }

  condition:
    any of them
}