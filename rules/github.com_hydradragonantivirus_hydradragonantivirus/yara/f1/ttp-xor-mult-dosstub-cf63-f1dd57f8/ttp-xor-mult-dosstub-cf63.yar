rule TTP_XOR_MULT_DOSStub_cf63 {
  strings:
    $key_cf63 = { 9b 0b [2] ef 13 [2] a8 11 [2] ef 00 [2] a1 0c [2] ad 06 [2] ba 0d [2] a1 43 [2] 9c }

  condition:
    any of them
}