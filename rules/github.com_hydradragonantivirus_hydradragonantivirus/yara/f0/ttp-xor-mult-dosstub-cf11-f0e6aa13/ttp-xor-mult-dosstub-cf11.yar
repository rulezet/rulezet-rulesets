rule TTP_XOR_MULT_DOSStub_cf11 {
  strings:
    $key_cf11 = { 9b 79 [2] ef 61 [2] a8 63 [2] ef 72 [2] a1 7e [2] ad 74 [2] ba 7f [2] a1 31 [2] 9c }

  condition:
    any of them
}