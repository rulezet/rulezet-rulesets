rule TTP_XOR_MULT_DOSStub_cf6d {
  strings:
    $key_cf6d = { 9b 05 [2] ef 1d [2] a8 1f [2] ef 0e [2] a1 02 [2] ad 08 [2] ba 03 [2] a1 4d [2] 9c }

  condition:
    any of them
}