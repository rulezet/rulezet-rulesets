rule TTP_XOR_MULT_DOSStub_de32 {
  strings:
    $key_de32 = { 8a 5a [2] fe 42 [2] b9 40 [2] fe 51 [2] b0 5d [2] bc 57 [2] ab 5c [2] b0 12 [2] 8d }

  condition:
    any of them
}