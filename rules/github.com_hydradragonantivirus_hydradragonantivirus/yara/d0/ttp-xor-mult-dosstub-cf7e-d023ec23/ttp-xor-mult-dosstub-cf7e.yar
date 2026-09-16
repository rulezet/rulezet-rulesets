rule TTP_XOR_MULT_DOSStub_cf7e {
  strings:
    $key_cf7e = { 9b 16 [2] ef 0e [2] a8 0c [2] ef 1d [2] a1 11 [2] ad 1b [2] ba 10 [2] a1 5e [2] 9c }

  condition:
    any of them
}