rule TTP_XOR_MULT_DOSStub_cf40 {
  strings:
    $key_cf40 = { 9b 28 [2] ef 30 [2] a8 32 [2] ef 23 [2] a1 2f [2] ad 25 [2] ba 2e [2] a1 60 [2] 9c }

  condition:
    any of them
}