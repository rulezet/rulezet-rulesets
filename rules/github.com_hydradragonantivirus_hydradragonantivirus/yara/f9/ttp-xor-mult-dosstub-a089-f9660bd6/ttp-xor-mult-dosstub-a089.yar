rule TTP_XOR_MULT_DOSStub_a089 {
  strings:
    $key_a089 = { f4 e1 [2] 80 f9 [2] c7 fb [2] 80 ea [2] ce e6 [2] c2 ec [2] d5 e7 [2] ce a9 [2] f3 }

  condition:
    any of them
}