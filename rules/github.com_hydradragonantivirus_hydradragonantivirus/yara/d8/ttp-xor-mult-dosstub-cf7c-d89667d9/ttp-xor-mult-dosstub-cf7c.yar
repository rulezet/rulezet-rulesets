rule TTP_XOR_MULT_DOSStub_cf7c {
  strings:
    $key_cf7c = { 9b 14 [2] ef 0c [2] a8 0e [2] ef 1f [2] a1 13 [2] ad 19 [2] ba 12 [2] a1 5c [2] 9c }

  condition:
    any of them
}