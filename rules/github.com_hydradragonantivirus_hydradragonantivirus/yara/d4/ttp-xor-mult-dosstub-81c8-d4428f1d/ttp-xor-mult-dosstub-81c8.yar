rule TTP_XOR_MULT_DOSStub_81c8 {
  strings:
    $key_81c8 = { d5 a0 [2] a1 b8 [2] e6 ba [2] a1 ab [2] ef a7 [2] e3 ad [2] f4 a6 [2] ef e8 [2] d2 }

  condition:
    any of them
}