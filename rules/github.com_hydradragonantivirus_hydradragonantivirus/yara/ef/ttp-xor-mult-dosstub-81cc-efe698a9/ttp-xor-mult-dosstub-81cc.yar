rule TTP_XOR_MULT_DOSStub_81cc {
  strings:
    $key_81cc = { d5 a4 [2] a1 bc [2] e6 be [2] a1 af [2] ef a3 [2] e3 a9 [2] f4 a2 [2] ef ec [2] d2 }

  condition:
    any of them
}