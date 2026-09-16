rule TTP_XOR_MULT_DOSStub_cffc {
  strings:
    $key_cffc = { 9b 94 [2] ef 8c [2] a8 8e [2] ef 9f [2] a1 93 [2] ad 99 [2] ba 92 [2] a1 dc [2] 9c }

  condition:
    any of them
}