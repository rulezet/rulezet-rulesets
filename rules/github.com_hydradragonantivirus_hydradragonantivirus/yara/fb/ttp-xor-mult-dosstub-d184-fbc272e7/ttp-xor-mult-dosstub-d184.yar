rule TTP_XOR_MULT_DOSStub_d184 {
  strings:
    $key_d184 = { 85 ec [2] f1 f4 [2] b6 f6 [2] f1 e7 [2] bf eb [2] b3 e1 [2] a4 ea [2] bf a4 [2] 82 }

  condition:
    any of them
}