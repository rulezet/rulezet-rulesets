rule TTP_XOR_MULT_DOSStub_4682 {
  strings:
    $key_4682 = { 12 ea [2] 66 f2 [2] 21 f0 [2] 66 e1 [2] 28 ed [2] 24 e7 [2] 33 ec [2] 28 a2 [2] 15 }

  condition:
    any of them
}