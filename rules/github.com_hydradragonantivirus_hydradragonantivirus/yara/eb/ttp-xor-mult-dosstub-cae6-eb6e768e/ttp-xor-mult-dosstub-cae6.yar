rule TTP_XOR_MULT_DOSStub_cae6 {
  strings:
    $key_cae6 = { 9e 8e [2] ea 96 [2] ad 94 [2] ea 85 [2] a4 89 [2] a8 83 [2] bf 88 [2] a4 c6 [2] 99 }

  condition:
    any of them
}