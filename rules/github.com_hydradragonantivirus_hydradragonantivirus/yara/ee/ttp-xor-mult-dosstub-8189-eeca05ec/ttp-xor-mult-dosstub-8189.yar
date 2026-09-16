rule TTP_XOR_MULT_DOSStub_8189 {
  strings:
    $key_8189 = { d5 e1 [2] a1 f9 [2] e6 fb [2] a1 ea [2] ef e6 [2] e3 ec [2] f4 e7 [2] ef a9 [2] d2 }

  condition:
    any of them
}