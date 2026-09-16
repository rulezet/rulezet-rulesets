rule TTP_XOR_MULT_DOSStub_cf28 {
  strings:
    $key_cf28 = { 9b 40 [2] ef 58 [2] a8 5a [2] ef 4b [2] a1 47 [2] ad 4d [2] ba 46 [2] a1 08 [2] 9c }

  condition:
    any of them
}