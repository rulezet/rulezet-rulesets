rule TTP_XOR_MULT_DOSStub_cfe6 {
  strings:
    $key_cfe6 = { 9b 8e [2] ef 96 [2] a8 94 [2] ef 85 [2] a1 89 [2] ad 83 [2] ba 88 [2] a1 c6 [2] 9c }

  condition:
    any of them
}