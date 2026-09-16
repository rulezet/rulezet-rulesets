rule TTP_XOR_MULT_DOSStub_acf1 {
  strings:
    $key_acf1 = { f8 99 [2] 8c 81 [2] cb 83 [2] 8c 92 [2] c2 9e [2] ce 94 [2] d9 9f [2] c2 d1 [2] ff }

  condition:
    any of them
}