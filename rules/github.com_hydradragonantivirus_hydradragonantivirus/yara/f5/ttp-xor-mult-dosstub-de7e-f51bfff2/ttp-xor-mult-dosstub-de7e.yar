rule TTP_XOR_MULT_DOSStub_de7e {
  strings:
    $key_de7e = { 8a 16 [2] fe 0e [2] b9 0c [2] fe 1d [2] b0 11 [2] bc 1b [2] ab 10 [2] b0 5e [2] 8d }

  condition:
    any of them
}