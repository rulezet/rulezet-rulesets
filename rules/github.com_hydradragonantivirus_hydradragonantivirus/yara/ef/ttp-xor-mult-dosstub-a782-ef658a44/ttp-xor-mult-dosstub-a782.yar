rule TTP_XOR_MULT_DOSStub_a782 {
  strings:
    $key_a782 = { f3 ea [2] 87 f2 [2] c0 f0 [2] 87 e1 [2] c9 ed [2] c5 e7 [2] d2 ec [2] c9 a2 [2] f4 }

  condition:
    any of them
}