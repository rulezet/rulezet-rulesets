rule TTP_XOR_MULT_DOSStub_de3c {
  strings:
    $key_de3c = { 8a 54 [2] fe 4c [2] b9 4e [2] fe 5f [2] b0 53 [2] bc 59 [2] ab 52 [2] b0 1c [2] 8d }

  condition:
    any of them
}