rule TTP_XOR_MULT_DOSStub_de12 {
  strings:
    $key_de12 = { 8a 7a [2] fe 62 [2] b9 60 [2] fe 71 [2] b0 7d [2] bc 77 [2] ab 7c [2] b0 32 [2] 8d }

  condition:
    any of them
}