rule TTP_XOR_MULT_DOSStub_cf0b {
  strings:
    $key_cf0b = { 9b 63 [2] ef 7b [2] a8 79 [2] ef 68 [2] a1 64 [2] ad 6e [2] ba 65 [2] a1 2b [2] 9c }

  condition:
    any of them
}