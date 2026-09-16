rule TTP_XOR_MULT_DOSStub_acb9 {
  strings:
    $key_acb9 = { f8 d1 [2] 8c c9 [2] cb cb [2] 8c da [2] c2 d6 [2] ce dc [2] d9 d7 [2] c2 99 [2] ff }

  condition:
    any of them
}