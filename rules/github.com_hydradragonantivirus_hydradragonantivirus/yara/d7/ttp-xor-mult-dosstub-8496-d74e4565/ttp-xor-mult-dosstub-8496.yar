rule TTP_XOR_MULT_DOSStub_8496 {
  strings:
    $key_8496 = { d0 fe [2] a4 e6 [2] e3 e4 [2] a4 f5 [2] ea f9 [2] e6 f3 [2] f1 f8 [2] ea b6 [2] d7 }

  condition:
    any of them
}