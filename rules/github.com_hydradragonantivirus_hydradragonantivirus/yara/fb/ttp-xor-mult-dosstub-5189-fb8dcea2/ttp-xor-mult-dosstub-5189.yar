rule TTP_XOR_MULT_DOSStub_5189 {
  strings:
    $key_5189 = { 05 e1 [2] 71 f9 [2] 36 fb [2] 71 ea [2] 3f e6 [2] 33 ec [2] 24 e7 [2] 3f a9 [2] 02 }

  condition:
    any of them
}