rule TTP_XOR_MULT_DOSStub_cf1b {
  strings:
    $key_cf1b = { 9b 73 [2] ef 6b [2] a8 69 [2] ef 78 [2] a1 74 [2] ad 7e [2] ba 75 [2] a1 3b [2] 9c }

  condition:
    any of them
}