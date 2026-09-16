rule TTP_XOR_MULT_DOSStub_cfea {
  strings:
    $key_cfea = { 9b 82 [2] ef 9a [2] a8 98 [2] ef 89 [2] a1 85 [2] ad 8f [2] ba 84 [2] a1 ca [2] 9c }

  condition:
    any of them
}