rule TTP_XOR_MULT_DOSStub_ac86 {
  strings:
    $key_ac86 = { f8 ee [2] 8c f6 [2] cb f4 [2] 8c e5 [2] c2 e9 [2] ce e3 [2] d9 e8 [2] c2 a6 [2] ff }

  condition:
    any of them
}