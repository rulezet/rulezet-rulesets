rule TTP_XOR_MULT_DOSStub_cf44 {
  strings:
    $key_cf44 = { 9b 2c [2] ef 34 [2] a8 36 [2] ef 27 [2] a1 2b [2] ad 21 [2] ba 2a [2] a1 64 [2] 9c }

  condition:
    any of them
}