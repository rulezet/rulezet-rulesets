rule TTP_XOR_MULT_DOSStub_81d2 {
  strings:
    $key_81d2 = { d5 ba [2] a1 a2 [2] e6 a0 [2] a1 b1 [2] ef bd [2] e3 b7 [2] f4 bc [2] ef f2 [2] d2 }

  condition:
    any of them
}