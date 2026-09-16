rule TTP_XOR_MULT_DOSStub_ac20 {
  strings:
    $key_ac20 = { f8 48 [2] 8c 50 [2] cb 52 [2] 8c 43 [2] c2 4f [2] ce 45 [2] d9 4e [2] c2 00 [2] ff }

  condition:
    any of them
}