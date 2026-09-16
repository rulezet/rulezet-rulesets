rule TTP_XOR_MULT_DOSStub_de2e {
  strings:
    $key_de2e = { 8a 46 [2] fe 5e [2] b9 5c [2] fe 4d [2] b0 41 [2] bc 4b [2] ab 40 [2] b0 0e [2] 8d }

  condition:
    any of them
}