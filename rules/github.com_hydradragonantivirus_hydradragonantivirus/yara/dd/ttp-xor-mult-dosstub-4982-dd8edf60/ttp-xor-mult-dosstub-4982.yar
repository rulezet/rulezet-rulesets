rule TTP_XOR_MULT_DOSStub_4982 {
  strings:
    $key_4982 = { 1d ea [2] 69 f2 [2] 2e f0 [2] 69 e1 [2] 27 ed [2] 2b e7 [2] 3c ec [2] 27 a2 [2] 1a }

  condition:
    any of them
}