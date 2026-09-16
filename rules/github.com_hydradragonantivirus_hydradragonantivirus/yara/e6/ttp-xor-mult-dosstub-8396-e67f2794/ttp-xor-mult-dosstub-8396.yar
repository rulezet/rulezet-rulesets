rule TTP_XOR_MULT_DOSStub_8396 {
  strings:
    $key_8396 = { d7 fe [2] a3 e6 [2] e4 e4 [2] a3 f5 [2] ed f9 [2] e1 f3 [2] f6 f8 [2] ed b6 [2] d0 }

  condition:
    any of them
}