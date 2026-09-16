rule TTP_XOR_MULT_DOSStub_ca36 {
  strings:
    $key_ca36 = { 9e 5e [2] ea 46 [2] ad 44 [2] ea 55 [2] a4 59 [2] a8 53 [2] bf 58 [2] a4 16 [2] 99 }

  condition:
    any of them
}