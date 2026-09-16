rule TTP_XOR_MULT_DOSStub_84c6 {
  strings:
    $key_84c6 = { d0 ae [2] a4 b6 [2] e3 b4 [2] a4 a5 [2] ea a9 [2] e6 a3 [2] f1 a8 [2] ea e6 [2] d7 }

  condition:
    any of them
}