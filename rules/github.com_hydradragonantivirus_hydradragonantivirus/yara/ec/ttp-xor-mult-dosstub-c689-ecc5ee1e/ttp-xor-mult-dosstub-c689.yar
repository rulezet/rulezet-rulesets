rule TTP_XOR_MULT_DOSStub_c689 {
  strings:
    $key_c689 = { 92 e1 [2] e6 f9 [2] a1 fb [2] e6 ea [2] a8 e6 [2] a4 ec [2] b3 e7 [2] a8 a9 [2] 95 }

  condition:
    any of them
}