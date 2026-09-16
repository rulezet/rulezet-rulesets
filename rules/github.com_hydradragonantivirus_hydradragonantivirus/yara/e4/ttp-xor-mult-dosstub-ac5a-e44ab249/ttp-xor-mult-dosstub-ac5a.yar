rule TTP_XOR_MULT_DOSStub_ac5a {
  strings:
    $key_ac5a = { f8 32 [2] 8c 2a [2] cb 28 [2] 8c 39 [2] c2 35 [2] ce 3f [2] d9 34 [2] c2 7a [2] ff }

  condition:
    any of them
}