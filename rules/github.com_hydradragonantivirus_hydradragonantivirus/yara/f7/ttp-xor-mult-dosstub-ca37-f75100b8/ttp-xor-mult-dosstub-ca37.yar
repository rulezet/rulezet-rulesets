rule TTP_XOR_MULT_DOSStub_ca37 {
  strings:
    $key_ca37 = { 9e 5f [2] ea 47 [2] ad 45 [2] ea 54 [2] a4 58 [2] a8 52 [2] bf 59 [2] a4 17 [2] 99 }

  condition:
    any of them
}