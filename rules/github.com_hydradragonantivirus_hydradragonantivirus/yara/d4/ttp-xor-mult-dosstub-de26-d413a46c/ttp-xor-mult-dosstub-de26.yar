rule TTP_XOR_MULT_DOSStub_de26 {
  strings:
    $key_de26 = { 8a 4e [2] fe 56 [2] b9 54 [2] fe 45 [2] b0 49 [2] bc 43 [2] ab 48 [2] b0 06 [2] 8d }

  condition:
    any of them
}