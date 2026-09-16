rule TTP_XOR_MULT_DOSStub_8405 {
  strings:
    $key_8405 = { d0 6d [2] a4 75 [2] e3 77 [2] a4 66 [2] ea 6a [2] e6 60 [2] f1 6b [2] ea 25 [2] d7 }

  condition:
    any of them
}