rule TTP_XOR_MULT_DOSStub_ca60 {
  strings:
    $key_ca60 = { 9e 08 [2] ea 10 [2] ad 12 [2] ea 03 [2] a4 0f [2] a8 05 [2] bf 0e [2] a4 40 [2] 99 }

  condition:
    any of them
}