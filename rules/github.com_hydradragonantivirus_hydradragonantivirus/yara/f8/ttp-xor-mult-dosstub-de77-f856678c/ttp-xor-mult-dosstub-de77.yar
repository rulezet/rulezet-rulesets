rule TTP_XOR_MULT_DOSStub_de77 {
  strings:
    $key_de77 = { 8a 1f [2] fe 07 [2] b9 05 [2] fe 14 [2] b0 18 [2] bc 12 [2] ab 19 [2] b0 57 [2] 8d }

  condition:
    any of them
}