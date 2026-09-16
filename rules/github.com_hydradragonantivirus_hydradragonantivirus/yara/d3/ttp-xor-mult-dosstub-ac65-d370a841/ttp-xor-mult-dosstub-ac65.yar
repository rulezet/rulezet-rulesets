rule TTP_XOR_MULT_DOSStub_ac65 {
  strings:
    $key_ac65 = { f8 0d [2] 8c 15 [2] cb 17 [2] 8c 06 [2] c2 0a [2] ce 00 [2] d9 0b [2] c2 45 [2] ff }

  condition:
    any of them
}