rule TTP_XOR_MULT_DOSStub_cf39 {
  strings:
    $key_cf39 = { 9b 51 [2] ef 49 [2] a8 4b [2] ef 5a [2] a1 56 [2] ad 5c [2] ba 57 [2] a1 19 [2] 9c }

  condition:
    any of them
}