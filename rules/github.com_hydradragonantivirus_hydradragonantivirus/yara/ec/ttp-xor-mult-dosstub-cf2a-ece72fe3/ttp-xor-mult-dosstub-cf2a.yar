rule TTP_XOR_MULT_DOSStub_cf2a {
  strings:
    $key_cf2a = { 9b 42 [2] ef 5a [2] a8 58 [2] ef 49 [2] a1 45 [2] ad 4f [2] ba 44 [2] a1 0a [2] 9c }

  condition:
    any of them
}