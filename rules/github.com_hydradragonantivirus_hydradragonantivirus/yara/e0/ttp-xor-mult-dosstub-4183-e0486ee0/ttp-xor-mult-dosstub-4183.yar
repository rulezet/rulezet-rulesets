rule TTP_XOR_MULT_DOSStub_4183 {
  strings:
    $key_4183 = { 15 eb [2] 61 f3 [2] 26 f1 [2] 61 e0 [2] 2f ec [2] 23 e6 [2] 34 ed [2] 2f a3 [2] 12 }

  condition:
    any of them
}