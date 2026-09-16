rule TTP_XOR_MULT_DOSStub_d689 {
  strings:
    $key_d689 = { 82 e1 [2] f6 f9 [2] b1 fb [2] f6 ea [2] b8 e6 [2] b4 ec [2] a3 e7 [2] b8 a9 [2] 85 }

  condition:
    any of them
}