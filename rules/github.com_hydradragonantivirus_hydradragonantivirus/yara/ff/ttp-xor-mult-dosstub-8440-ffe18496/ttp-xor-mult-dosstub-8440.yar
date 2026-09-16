rule TTP_XOR_MULT_DOSStub_8440 {
  strings:
    $key_8440 = { d0 28 [2] a4 30 [2] e3 32 [2] a4 23 [2] ea 2f [2] e6 25 [2] f1 2e [2] ea 60 [2] d7 }

  condition:
    any of them
}