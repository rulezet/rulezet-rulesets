rule TTP_XOR_MULT_DOSStub_cf2c {
  strings:
    $key_cf2c = { 9b 44 [2] ef 5c [2] a8 5e [2] ef 4f [2] a1 43 [2] ad 49 [2] ba 42 [2] a1 0c [2] 9c }

  condition:
    any of them
}