rule TTP_XOR_MULT_DOSStub_e584 {
  strings:
    $key_e584 = { b1 ec [2] c5 f4 [2] 82 f6 [2] c5 e7 [2] 8b eb [2] 87 e1 [2] 90 ea [2] 8b a4 [2] b6 }

  condition:
    any of them
}