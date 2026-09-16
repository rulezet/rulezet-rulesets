rule TTP_XOR_MULT_DOSStub_aca9 {
  strings:
    $key_aca9 = { f8 c1 [2] 8c d9 [2] cb db [2] 8c ca [2] c2 c6 [2] ce cc [2] d9 c7 [2] c2 89 [2] ff }

  condition:
    any of them
}