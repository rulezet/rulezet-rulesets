rule TTP_XOR_MULT_DOSStub_de5b {
  strings:
    $key_de5b = { 8a 33 [2] fe 2b [2] b9 29 [2] fe 38 [2] b0 34 [2] bc 3e [2] ab 35 [2] b0 7b [2] 8d }

  condition:
    any of them
}