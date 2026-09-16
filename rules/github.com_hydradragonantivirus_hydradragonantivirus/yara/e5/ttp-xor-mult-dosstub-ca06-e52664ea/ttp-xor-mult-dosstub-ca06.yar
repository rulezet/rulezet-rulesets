rule TTP_XOR_MULT_DOSStub_ca06 {
  strings:
    $key_ca06 = { 9e 6e [2] ea 76 [2] ad 74 [2] ea 65 [2] a4 69 [2] a8 63 [2] bf 68 [2] a4 26 [2] 99 }

  condition:
    any of them
}