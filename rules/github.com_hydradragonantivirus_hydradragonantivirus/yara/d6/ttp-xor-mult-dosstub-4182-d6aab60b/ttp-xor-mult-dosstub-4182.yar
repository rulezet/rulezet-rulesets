rule TTP_XOR_MULT_DOSStub_4182 {
  strings:
    $key_4182 = { 15 ea [2] 61 f2 [2] 26 f0 [2] 61 e1 [2] 2f ed [2] 23 e7 [2] 34 ec [2] 2f a2 [2] 12 }

  condition:
    any of them
}