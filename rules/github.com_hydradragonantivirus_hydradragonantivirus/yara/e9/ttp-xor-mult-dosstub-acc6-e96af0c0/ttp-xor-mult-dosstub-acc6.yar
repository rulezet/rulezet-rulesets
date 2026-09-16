rule TTP_XOR_MULT_DOSStub_acc6 {
  strings:
    $key_acc6 = { f8 ae [2] 8c b6 [2] cb b4 [2] 8c a5 [2] c2 a9 [2] ce a3 [2] d9 a8 [2] c2 e6 [2] ff }

  condition:
    any of them
}