rule TTP_XOR_MULT_DOSStub_cf5c {
  strings:
    $key_cf5c = { 9b 34 [2] ef 2c [2] a8 2e [2] ef 3f [2] a1 33 [2] ad 39 [2] ba 32 [2] a1 7c [2] 9c }

  condition:
    any of them
}