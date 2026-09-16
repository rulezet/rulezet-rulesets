rule TTP_XOR_MULT_DOSStub_cf7f {
  strings:
    $key_cf7f = { 9b 17 [2] ef 0f [2] a8 0d [2] ef 1c [2] a1 10 [2] ad 1a [2] ba 11 [2] a1 5f [2] 9c }

  condition:
    any of them
}