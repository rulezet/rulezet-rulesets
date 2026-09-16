rule TTP_XOR_MULT_DOSStub_ca40 {
  strings:
    $key_ca40 = { 9e 28 [2] ea 30 [2] ad 32 [2] ea 23 [2] a4 2f [2] a8 25 [2] bf 2e [2] a4 60 [2] 99 }

  condition:
    any of them
}