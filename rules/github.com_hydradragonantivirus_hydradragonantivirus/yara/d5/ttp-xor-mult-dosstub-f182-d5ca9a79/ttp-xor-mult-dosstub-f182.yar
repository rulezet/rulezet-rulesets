rule TTP_XOR_MULT_DOSStub_f182 {
  strings:
    $key_f182 = { a5 ea [2] d1 f2 [2] 96 f0 [2] d1 e1 [2] 9f ed [2] 93 e7 [2] 84 ec [2] 9f a2 [2] a2 }

  condition:
    any of them
}