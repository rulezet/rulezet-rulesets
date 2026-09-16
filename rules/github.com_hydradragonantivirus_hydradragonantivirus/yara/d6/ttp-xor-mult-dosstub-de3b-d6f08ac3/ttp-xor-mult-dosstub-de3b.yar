rule TTP_XOR_MULT_DOSStub_de3b {
  strings:
    $key_de3b = { 8a 53 [2] fe 4b [2] b9 49 [2] fe 58 [2] b0 54 [2] bc 5e [2] ab 55 [2] b0 1b [2] 8d }

  condition:
    any of them
}