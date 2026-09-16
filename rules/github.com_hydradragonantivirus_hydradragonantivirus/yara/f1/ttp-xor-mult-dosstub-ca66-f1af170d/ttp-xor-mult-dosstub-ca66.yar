rule TTP_XOR_MULT_DOSStub_ca66 {
  strings:
    $key_ca66 = { 9e 0e [2] ea 16 [2] ad 14 [2] ea 05 [2] a4 09 [2] a8 03 [2] bf 08 [2] a4 46 [2] 99 }

  condition:
    any of them
}