rule TTP_XOR_MULT_DOSStub_de13 {
  strings:
    $key_de13 = { 8a 7b [2] fe 63 [2] b9 61 [2] fe 70 [2] b0 7c [2] bc 76 [2] ab 7d [2] b0 33 [2] 8d }

  condition:
    any of them
}