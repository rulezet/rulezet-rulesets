rule TTP_XOR_MULT_DOSStub_de07 {
  strings:
    $key_de07 = { 8a 6f [2] fe 77 [2] b9 75 [2] fe 64 [2] b0 68 [2] bc 62 [2] ab 69 [2] b0 27 [2] 8d }

  condition:
    any of them
}