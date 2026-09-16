rule TTP_XOR_MULT_DOSStub_81d9 {
  strings:
    $key_81d9 = { d5 b1 [2] a1 a9 [2] e6 ab [2] a1 ba [2] ef b6 [2] e3 bc [2] f4 b7 [2] ef f9 [2] d2 }

  condition:
    any of them
}