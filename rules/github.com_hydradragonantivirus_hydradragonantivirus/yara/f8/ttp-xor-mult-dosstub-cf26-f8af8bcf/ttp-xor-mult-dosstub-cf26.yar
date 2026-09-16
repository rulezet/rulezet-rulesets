rule TTP_XOR_MULT_DOSStub_cf26 {
  strings:
    $key_cf26 = { 9b 4e [2] ef 56 [2] a8 54 [2] ef 45 [2] a1 49 [2] ad 43 [2] ba 48 [2] a1 06 [2] 9c }

  condition:
    any of them
}