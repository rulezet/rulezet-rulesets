rule TTP_XOR_MULT_DOSStub_cff6 {
  strings:
    $key_cff6 = { 9b 9e [2] ef 86 [2] a8 84 [2] ef 95 [2] a1 99 [2] ad 93 [2] ba 98 [2] a1 d6 [2] 9c }

  condition:
    any of them
}