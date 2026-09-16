rule TTP_XOR_MULT_DOSStub_de97 {
  strings:
    $key_de97 = { 8a ff [2] fe e7 [2] b9 e5 [2] fe f4 [2] b0 f8 [2] bc f2 [2] ab f9 [2] b0 b7 [2] 8d }

  condition:
    any of them
}