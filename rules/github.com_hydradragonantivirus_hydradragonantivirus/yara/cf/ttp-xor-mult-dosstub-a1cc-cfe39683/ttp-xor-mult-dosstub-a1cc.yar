rule TTP_XOR_MULT_DOSStub_a1cc {
  strings:
    $key_a1cc = { f5 a4 [2] 81 bc [2] c6 be [2] 81 af [2] cf a3 [2] c3 a9 [2] d4 a2 [2] cf ec [2] f2 }

  condition:
    any of them
}