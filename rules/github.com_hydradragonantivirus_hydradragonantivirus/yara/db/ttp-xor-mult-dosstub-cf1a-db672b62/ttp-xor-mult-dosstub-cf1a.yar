rule TTP_XOR_MULT_DOSStub_cf1a {
  strings:
    $key_cf1a = { 9b 72 [2] ef 6a [2] a8 68 [2] ef 79 [2] a1 75 [2] ad 7f [2] ba 74 [2] a1 3a [2] 9c }

  condition:
    any of them
}