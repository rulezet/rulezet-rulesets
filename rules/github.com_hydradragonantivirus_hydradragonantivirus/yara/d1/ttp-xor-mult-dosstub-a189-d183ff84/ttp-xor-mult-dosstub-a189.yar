rule TTP_XOR_MULT_DOSStub_a189 {
  strings:
    $key_a189 = { f5 e1 [2] 81 f9 [2] c6 fb [2] 81 ea [2] cf e6 [2] c3 ec [2] d4 e7 [2] cf a9 [2] f2 }

  condition:
    any of them
}