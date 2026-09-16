rule TTP_XOR_MULT_DOSStub_cf66 {
  strings:
    $key_cf66 = { 9b 0e [2] ef 16 [2] a8 14 [2] ef 05 [2] a1 09 [2] ad 03 [2] ba 08 [2] a1 46 [2] 9c }

  condition:
    any of them
}