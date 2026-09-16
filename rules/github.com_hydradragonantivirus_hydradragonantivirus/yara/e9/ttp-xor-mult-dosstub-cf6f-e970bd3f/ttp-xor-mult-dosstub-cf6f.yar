rule TTP_XOR_MULT_DOSStub_cf6f {
  strings:
    $key_cf6f = { 9b 07 [2] ef 1f [2] a8 1d [2] ef 0c [2] a1 00 [2] ad 0a [2] ba 01 [2] a1 4f [2] 9c }

  condition:
    any of them
}