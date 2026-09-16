rule TTP_XOR_MULT_DOSStub_ca41 {
  strings:
    $key_ca41 = { 9e 29 [2] ea 31 [2] ad 33 [2] ea 22 [2] a4 2e [2] a8 24 [2] bf 2f [2] a4 61 [2] 99 }

  condition:
    any of them
}