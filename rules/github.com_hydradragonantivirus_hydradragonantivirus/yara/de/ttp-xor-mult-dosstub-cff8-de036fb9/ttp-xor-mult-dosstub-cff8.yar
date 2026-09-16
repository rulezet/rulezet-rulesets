rule TTP_XOR_MULT_DOSStub_cff8 {
  strings:
    $key_cff8 = { 9b 90 [2] ef 88 [2] a8 8a [2] ef 9b [2] a1 97 [2] ad 9d [2] ba 96 [2] a1 d8 [2] 9c }

  condition:
    any of them
}