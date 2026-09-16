rule TTP_XOR_MULT_DOSStub_4082 {
  strings:
    $key_4082 = { 14 ea [2] 60 f2 [2] 27 f0 [2] 60 e1 [2] 2e ed [2] 22 e7 [2] 35 ec [2] 2e a2 [2] 13 }

  condition:
    any of them
}