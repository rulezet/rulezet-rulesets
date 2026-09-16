rule TTP_XOR_MULT_DOSStub_81ca {
  strings:
    $key_81ca = { d5 a2 [2] a1 ba [2] e6 b8 [2] a1 a9 [2] ef a5 [2] e3 af [2] f4 a4 [2] ef ea [2] d2 }

  condition:
    any of them
}