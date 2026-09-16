rule TTP_XOR_MULT_DOSStub_cf30 {
  strings:
    $key_cf30 = { 9b 58 [2] ef 40 [2] a8 42 [2] ef 53 [2] a1 5f [2] ad 55 [2] ba 5e [2] a1 10 [2] 9c }

  condition:
    any of them
}