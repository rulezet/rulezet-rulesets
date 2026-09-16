rule TTP_XOR_MULT_DOSStub_8586 {
  strings:
    $key_8586 = { d1 ee [2] a5 f6 [2] e2 f4 [2] a5 e5 [2] eb e9 [2] e7 e3 [2] f0 e8 [2] eb a6 [2] d6 }

  condition:
    any of them
}