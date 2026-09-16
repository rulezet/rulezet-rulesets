rule TTP_XOR_MULT_DOSStub_ac72 {
  strings:
    $key_ac72 = { f8 1a [2] 8c 02 [2] cb 00 [2] 8c 11 [2] c2 1d [2] ce 17 [2] d9 1c [2] c2 52 [2] ff }

  condition:
    any of them
}