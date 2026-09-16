rule TTP_XOR_MULT_DOSStub_de91 {
  strings:
    $key_de91 = { 8a f9 [2] fe e1 [2] b9 e3 [2] fe f2 [2] b0 fe [2] bc f4 [2] ab ff [2] b0 b1 [2] 8d }

  condition:
    any of them
}