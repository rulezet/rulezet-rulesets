rule TTP_XOR_MULT_DOSStub_81c1 {
  strings:
    $key_81c1 = { d5 a9 [2] a1 b1 [2] e6 b3 [2] a1 a2 [2] ef ae [2] e3 a4 [2] f4 af [2] ef e1 [2] d2 }

  condition:
    any of them
}