rule TTP_XOR_MULT_DOSStub_cf6a {
  strings:
    $key_cf6a = { 9b 02 [2] ef 1a [2] a8 18 [2] ef 09 [2] a1 05 [2] ad 0f [2] ba 04 [2] a1 4a [2] 9c }

  condition:
    any of them
}