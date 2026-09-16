rule TTP_XOR_MULT_DOSStub_8686 {
  strings:
    $key_8686 = { d2 ee [2] a6 f6 [2] e1 f4 [2] a6 e5 [2] e8 e9 [2] e4 e3 [2] f3 e8 [2] e8 a6 [2] d5 }

  condition:
    any of them
}