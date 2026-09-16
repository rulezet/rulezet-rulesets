rule TTP_XOR_MULT_DOSStub_cf25 {
  strings:
    $key_cf25 = { 9b 4d [2] ef 55 [2] a8 57 [2] ef 46 [2] a1 4a [2] ad 40 [2] ba 4b [2] a1 05 [2] 9c }

  condition:
    any of them
}