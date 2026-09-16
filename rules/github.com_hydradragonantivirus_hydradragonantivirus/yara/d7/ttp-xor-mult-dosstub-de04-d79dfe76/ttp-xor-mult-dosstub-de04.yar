rule TTP_XOR_MULT_DOSStub_de04 {
  strings:
    $key_de04 = { 8a 6c [2] fe 74 [2] b9 76 [2] fe 67 [2] b0 6b [2] bc 61 [2] ab 6a [2] b0 24 [2] 8d }

  condition:
    any of them
}