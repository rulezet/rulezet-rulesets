rule TTP_XOR_MULT_DOSStub_acb1 {
  strings:
    $key_acb1 = { f8 d9 [2] 8c c1 [2] cb c3 [2] 8c d2 [2] c2 de [2] ce d4 [2] d9 df [2] c2 91 [2] ff }

  condition:
    any of them
}