rule TTP_XOR_MULT_DOSStub_8486 {
  strings:
    $key_8486 = { d0 ee [2] a4 f6 [2] e3 f4 [2] a4 e5 [2] ea e9 [2] e6 e3 [2] f1 e8 [2] ea a6 [2] d7 }

  condition:
    any of them
}