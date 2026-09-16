rule TTP_XOR_MULT_DOSStub_de34 {
  strings:
    $key_de34 = { 8a 5c [2] fe 44 [2] b9 46 [2] fe 57 [2] b0 5b [2] bc 51 [2] ab 5a [2] b0 14 [2] 8d }

  condition:
    any of them
}