rule TTP_XOR_MULT_DOSStub_f285 {
  strings:
    $key_f285 = { a6 ed [2] d2 f5 [2] 95 f7 [2] d2 e6 [2] 9c ea [2] 90 e0 [2] 87 eb [2] 9c a5 [2] a1 }

  condition:
    any of them
}