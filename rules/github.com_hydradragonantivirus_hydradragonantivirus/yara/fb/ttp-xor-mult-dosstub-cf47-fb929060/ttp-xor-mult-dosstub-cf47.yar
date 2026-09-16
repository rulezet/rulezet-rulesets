rule TTP_XOR_MULT_DOSStub_cf47 {
  strings:
    $key_cf47 = { 9b 2f [2] ef 37 [2] a8 35 [2] ef 24 [2] a1 28 [2] ad 22 [2] ba 29 [2] a1 67 [2] 9c }

  condition:
    any of them
}