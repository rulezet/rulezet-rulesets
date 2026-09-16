rule TTP_XOR_MULT_DOSStub_ac16 {
  strings:
    $key_ac16 = { f8 7e [2] 8c 66 [2] cb 64 [2] 8c 75 [2] c2 79 [2] ce 73 [2] d9 78 [2] c2 36 [2] ff }

  condition:
    any of them
}