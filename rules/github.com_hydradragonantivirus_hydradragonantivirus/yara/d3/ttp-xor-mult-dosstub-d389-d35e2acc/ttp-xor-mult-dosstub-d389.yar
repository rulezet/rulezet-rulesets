rule TTP_XOR_MULT_DOSStub_d389 {
  strings:
    $key_d389 = { 87 e1 [2] f3 f9 [2] b4 fb [2] f3 ea [2] bd e6 [2] b1 ec [2] a6 e7 [2] bd a9 [2] 80 }

  condition:
    any of them
}