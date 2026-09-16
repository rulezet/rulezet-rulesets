rule TTP_XOR_MULT_DOSStub_a984 {
  strings:
    $key_a984 = { fd ec [2] 89 f4 [2] ce f6 [2] 89 e7 [2] c7 eb [2] cb e1 [2] dc ea [2] c7 a4 [2] fa }

  condition:
    any of them
}