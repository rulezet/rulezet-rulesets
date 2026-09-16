rule TTP_XOR_MULT_DOSStub_acb7 {
  strings:
    $key_acb7 = { f8 df [2] 8c c7 [2] cb c5 [2] 8c d4 [2] c2 d8 [2] ce d2 [2] d9 d9 [2] c2 97 [2] ff }

  condition:
    any of them
}