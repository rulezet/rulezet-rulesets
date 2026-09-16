rule TTP_XOR_MULT_DOSStub_81cb {
  strings:
    $key_81cb = { d5 a3 [2] a1 bb [2] e6 b9 [2] a1 a8 [2] ef a4 [2] e3 ae [2] f4 a5 [2] ef eb [2] d2 }

  condition:
    any of them
}