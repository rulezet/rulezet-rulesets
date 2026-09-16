rule TTP_XOR_MULT_DOSStub_8397 {
  strings:
    $key_8397 = { d7 ff [2] a3 e7 [2] e4 e5 [2] a3 f4 [2] ed f8 [2] e1 f2 [2] f6 f9 [2] ed b7 [2] d0 }

  condition:
    any of them
}