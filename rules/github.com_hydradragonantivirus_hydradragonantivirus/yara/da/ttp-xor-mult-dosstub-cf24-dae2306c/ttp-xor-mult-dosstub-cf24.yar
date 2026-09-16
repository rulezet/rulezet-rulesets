rule TTP_XOR_MULT_DOSStub_cf24 {
  strings:
    $key_cf24 = { 9b 4c [2] ef 54 [2] a8 56 [2] ef 47 [2] a1 4b [2] ad 41 [2] ba 4a [2] a1 04 [2] 9c }

  condition:
    any of them
}