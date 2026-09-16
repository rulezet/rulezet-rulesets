rule TTP_XOR_MULT_DOSStub_ca51 {
  strings:
    $key_ca51 = { 9e 39 [2] ea 21 [2] ad 23 [2] ea 32 [2] a4 3e [2] a8 34 [2] bf 3f [2] a4 71 [2] 99 }

  condition:
    any of them
}