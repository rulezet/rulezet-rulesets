rule TTP_XOR_MULT_DOSStub_cf7b {
  strings:
    $key_cf7b = { 9b 13 [2] ef 0b [2] a8 09 [2] ef 18 [2] a1 14 [2] ad 1e [2] ba 15 [2] a1 5b [2] 9c }

  condition:
    any of them
}