rule TTP_XOR_MULT_DOSStub_cf7a {
  strings:
    $key_cf7a = { 9b 12 [2] ef 0a [2] a8 08 [2] ef 19 [2] a1 15 [2] ad 1f [2] ba 14 [2] a1 5a [2] 9c }

  condition:
    any of them
}