rule TTP_XOR_MULT_DOSStub_ca11 {
  strings:
    $key_ca11 = { 9e 79 [2] ea 61 [2] ad 63 [2] ea 72 [2] a4 7e [2] a8 74 [2] bf 7f [2] a4 31 [2] 99 }

  condition:
    any of them
}