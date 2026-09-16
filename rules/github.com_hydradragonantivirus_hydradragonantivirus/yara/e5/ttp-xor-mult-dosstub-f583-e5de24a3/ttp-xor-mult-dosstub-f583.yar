rule TTP_XOR_MULT_DOSStub_f583 {
  strings:
    $key_f583 = { a1 eb [2] d5 f3 [2] 92 f1 [2] d5 e0 [2] 9b ec [2] 97 e6 [2] 80 ed [2] 9b a3 [2] a6 }

  condition:
    any of them
}