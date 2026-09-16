rule TTP_XOR_MULT_DOSStub_8414 {
  strings:
    $key_8414 = { d0 7c [2] a4 64 [2] e3 66 [2] a4 77 [2] ea 7b [2] e6 71 [2] f1 7a [2] ea 34 [2] d7 }

  condition:
    any of them
}