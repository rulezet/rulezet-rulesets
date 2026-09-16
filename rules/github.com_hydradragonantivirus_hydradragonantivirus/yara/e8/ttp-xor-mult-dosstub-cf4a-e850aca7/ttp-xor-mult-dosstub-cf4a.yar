rule TTP_XOR_MULT_DOSStub_cf4a {
  strings:
    $key_cf4a = { 9b 22 [2] ef 3a [2] a8 38 [2] ef 29 [2] a1 25 [2] ad 2f [2] ba 24 [2] a1 6a [2] 9c }

  condition:
    any of them
}